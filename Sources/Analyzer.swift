import Foundation
import UniformTypeIdentifiers

/// 分析编排器：加载 IPA → 校验 → 解包 → 逐模块分析 → 风险评分
final class IPAEngine {

    enum EngineError: Error, LocalizedError {
        case notZip
        case noPayload
        case noExecutable
        case analysisFailed(String)

        var errorDescription: String? {
            switch self {
            case .notZip: return "文件不是合法的 IPA（ZIP）包"
            case .noPayload: return "IPA 中未找到 Payload/*.app"
            case .noExecutable: return "未能在 .app 内定位主可执行文件（CFBundleExecutable）"
            case .analysisFailed(let m): return "分析失败：\(m)"
            }
        }
    }

    /// 进度回调（0~1）
    var progress: ((String, Double) -> Void)?

    func analyze(data: Data, fileName: String) throws -> AnalysisResult {
        var result = AnalysisResult()
        result.fileName = fileName
        result.fileSize = data.count
        let now = Date()
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
        result.analyzedAt = fmt.string(from: now)

        progress?("计算哈希", 0.02)
        result.md5 = AnalyzerHash.md5(data)
        result.sha1 = AnalyzerHash.sha1(data)
        result.sha256 = AnalyzerHash.sha256(data)
        result.sha512 = AnalyzerHash.sha512(data)

        progress?("解析 ZIP 结构", 0.06)
        let zip: ZipReader
        do { zip = try ZipReader(data: data) }
        catch { throw EngineError.notZip }

        // 统计目录/文件
        var dirs = 0
        for e in zip.entries where e.isDirectory { dirs += 1 }
        result.fileCount = zip.entries.count - dirs
        result.directoryCount = dirs
        result.tree = zip.entries
            .map { ZipEntryInfo(path: $0.name, size: $0.uncompSize, isDirectory: $0.isDirectory) }
            .sorted { $0.path < $1.path }

        // 定位 Payload/*.app
        var appSet = Set<String>()
        for e in zip.entries {
            guard e.name.hasPrefix("Payload/") else { continue }
            let rest = e.name.dropFirst("Payload/".count)
            let top: Substring
            if let slash = rest.firstIndex(of: "/") {
                top = rest[..<slash]
            } else {
                top = rest
            }
            if top.hasSuffix(".app") { appSet.insert(String(top)) }
        }
        guard let mainAppName = appSet.sorted().first else {
            throw EngineError.noPayload
        }
        let appDir = "Payload/\(mainAppName)/"
        result.mainAppPath = appDir

        progress?("读取 Info.plist", 0.14)
        var plistInfo = PlistInfo.empty
        if let plistData = zip.read("\(appDir)Info.plist") {
            if let p = AnalyzerPlist.parse(plistData) { plistInfo = p }
        }

        // 提取签名证书（embedded.mobileprovision）
        progress?("解析签名证书", 0.18)
        var signing = ProvisioningInfo.empty
        if let prov = zip.read("\(appDir)embedded.mobileprovision") {
            signing = AnalyzerPlist.parseProvisioning(prov)
            result.provisioningDataBase64 = prov.base64EncodedString()
        }
        result.signing = signing.hasProfile ? signing : nil

        // 提取主程序
        let exeName = plistInfo.name.isEmpty ? mainAppName : plistInfo.name
        let exePath = "\(appDir)\(exeName)"
        var machOData = zip.read(exePath)
        // 回退：若可执行名解析不到，用 .app 同名的二进制
        if machOData == nil { machOData = zip.read("\(appDir)\(mainAppName)") }
        // 再回退：找 .app 下第一个 Mach-O 文件
        var machOInfo = MachOInfo.empty
        if let m = machOData {
            progress?("解析 Mach-O", 0.3)
            machOInfo = AnalyzerMachO.parse(m) ?? MachOInfo.empty
            if machOInfo.encrypted {
                result.encryptionNote = "主程序带 FairPlay 加密（LC_ENCRYPTION_INFO），内部字符串/符号无法解析，仅展示头部信息。"
            }
        } else {
            // 扫描 .app 下非 plist 大文件找 Mach-O
            for e in zip.entries where !e.isDirectory && e.name.hasPrefix(appDir) && e.uncompSize > 8_000 {
                if let d = zip.read(e.name), AnalyzerMachO.parse(d) != nil {
                    machOData = d
                    machOInfo = AnalyzerMachO.parse(d) ?? MachOInfo.empty
                    break
                }
            }
        }
        if machOData == nil { throw EngineError.noExecutable }

        progress?("扫描字符串与 URL", 0.5)
        let findings = AnalyzerStrings.scan(machOData!)
        result.strings = Array(findings.prefix(1200))
        var urls = [URLFinding]()
        var seenURL = Set<String>()
        for s in findings {
            if let host = AnalyzerStrings.extractURL(s.text) {
                let kind = AnalyzerStrings.urlKind(s.text)
                let susp = (kind != "https" && kind != "wss") || AnalyzerStrings.isPrivateIP(s.text)
                let display = (kind == "http" || kind == "https") ? "\(kind)://\(host)" : "\(kind)://\(host)"
                if !seenURL.contains(display) {
                    seenURL.insert(display)
                    urls.append(URLFinding(url: display, kind: kind, suspicious: susp))
                }
            } else if s.kind == "ip" && AnalyzerStrings.isIP(s.text) {
                if !seenURL.contains(s.text) {
                    seenURL.insert(s.text)
                    urls.append(URLFinding(url: s.text, kind: "ip", suspicious: AnalyzerStrings.isPrivateIP(s.text)))
                }
            } else if s.kind == "domain" {
                if !seenURL.contains(s.text) {
                    seenURL.insert(s.text)
                    urls.append(URLFinding(url: s.text, kind: "domain", suspicious: false))
                }
            }
        }
        result.urls = Array(urls.prefix(800))

        // 凭据 / 密码提取
        progress?("提取凭据", 0.6)
        result.credentials = AnalyzerStrings.extractCredentials(from: Array(result.strings), source: "主程序")

        // 深入内容审查：扫描包内多个文本/配置文件
        progress?("内容审查", 0.66)
        let audit = contentAudit(zip: zip, appDir: appDir, machO: machOData!)
        result.resourceAudit = audit.isEmpty ? nil : audit

        progress?("提取依赖库", 0.7)
        var deps = [DependencyInfo]()
        let systemKnown: [String] = ["UIKit", "Foundation", "CoreFoundation", "CoreData", "CoreGraphics",
                                     "QuartzCore", "CoreImage", "Metal", "MetalKit", "MetalPerformanceShaders",
                                     "AVFoundation", "AVFAudio", "AudioToolbox", "AVKit", "Photos", "PhotosUI",
                                     "MapKit", "CoreLocation", "AddressBook", "Contacts", "ContactsUI",
                                     "EventKit", "EventKitUI", "WebKit", "SafariServices", "StoreKit", "CloudKit",
                                     "Security", "LocalAuthentication", "AuthenticationServices", "CoreTelephony",
                                     "Network", "NetworkExtension", "SystemConfiguration", "CoreBluetooth",
                                     "CoreMotion", "GameKit", "GameplayKit", "SceneKit", "SpriteKit", "ARKit",
                                     "Vision", "CoreML", "Accelerate", "NaturalLanguage", "Speech", "PushKit",
                                     "UserNotifications", "UserNotificationsUI", "HealthKit", "HomeKit",
                                     "CoreSpotlight", "WidgetKit", "AppIntents", "BackgroundTasks",
                                     "CoreServices", "ImageIO", "UniformTypeIdentifiers", "CoreMedia",
                                     "VideoToolbox", "CoreAudio", "MediaPlayer", "MessageUI", "Social",
                                     "Twitter", "AdSupport", "iAd", "TVServices", "NewsstandKit",
                                     "PassKit", "WatchKit", "CallKit", "Intents", "IntentsUI", "NotificationCenter",
                                     "GameController", "MultipeerConnectivity", "ExternalAccessory",
                                     "MediaAccessibility", "CoreHaptics", "CoreAudioKit", "DeviceCheck",
                                     "FileProvider", "MetricKit", "PDFKit", "PencilKit", "ReplayKit",
                                     "ScreenTime", "Sensors", "SoundAnalysis", "SwiftUI", "Combine", "DataDetection"]
        let thirdPartySuspicious: [String: String] = [
            "Frida": "动态插桩/逆向库，危险", "libfrida": "动态插桩/逆向库，危险",
            "CydiaSubstrate": "越狱 Hook 库，危险", "MobileSubstrate": "越狱 Hook 库，危险",
            "fishhook": "符号 Hook 库，危险", "libhooker": "越狱 Hook 库，危险",
            "libinjection": "代码注入库，危险", "dylib injection": "注入类库，危险",
            "OpenSSL": "第三方加密库", "libssl": "第三方加密库", "libcrypto": "第三方加密库",
            "FFmpeg": "第三方多媒体库", "libav": "第三方多媒体库", "WebRTC": "第三方音视频库",
            "Realm": "第三方数据库", "SQLite": "数据库库", "SocketRocket": "第三方 WebSocket 库",
            "Alamofire": "第三方网络库", "AFNetworking": "第三方网络库", "SDWebImage": "第三方图片库",
            "MBProgressHUD": "第三方 UI 库", "MJRefresh": "第三方 UI 库", "YYKit": "第三方工具库",
            "SnapKit": "第三方布局库", "R.swift": "第三方资源库",
        ]
        var addedNames = Set<String>()
        for lib in machOInfo.linkedDylibs {
            let base = lib.split(separator: "/").last.map(String.init) ?? lib
            let clean = base.replacingOccurrences(of: ".framework", with: "")
            if addedNames.contains(clean) { continue }
            addedNames.insert(clean)
            if systemKnown.contains(clean) {
                deps.append(DependencyInfo(name: clean, kind: "system", note: "系统框架"))
            } else if let note = thirdPartySuspicious[clean] ?? thirdPartySuspicious[base] {
                let kind = note.contains("危险") ? "thirdparty" : "thirdparty"
                deps.append(DependencyInfo(name: clean, kind: kind, note: note))
            } else if base.hasSuffix(".dylib") || lib.hasPrefix("@") {
                deps.append(DependencyInfo(name: clean, kind: "embedded", note: "内嵌/私有动态库"))
            } else {
                deps.append(DependencyInfo(name: clean, kind: "thirdparty", note: "未识别第三方库"))
            }
        }
        result.deps = deps

        // 图标
        progress?("提取图标", 0.82)
        result.iconDataBase64 = extractIcon(zip: zip, appDir: appDir, plist: plistInfo)

        // embedded.mobileprovision（可选信息，并入风险 note 不单独展示）
        _ = zip.read("\(appDir)embedded.mobileprovision")

        // 风险
        progress?("风险评分", 0.92)
        let risk = AnalyzerRisk.evaluate(plist: plistInfo, machO: machOInfo,
                                         strings: Array(result.strings),
                                         credentials: result.credentials ?? [],
                                         resources: result.resourceAudit ?? [],
                                         urls: result.urls, deps: deps)
        result.findings = risk.findings
        result.score = risk.score
        result.riskLevel = RiskLevel.fromScore(risk.score)
        result.plist = plistInfo
        result.machO = machOInfo

        progress?("完成", 1.0)
        return result
    }

    // MARK: - 内容审查（扫描包内文本/配置文件，做逐文件结论）

    private func contentAudit(zip: ZipReader, appDir: String, machO: Data) -> [ResourceFinding] {
        var audit = [ResourceFinding]()
        // 主程序（已单独扫描）
        let exeFindings = AnalyzerStrings.scan(machO)
        let exeSens = sensitiveHits(exeFindings)
        if !exeSens.isEmpty {
            audit.append(ResourceFinding(path: "主程序", severity: .high, findings: exeSens))
        }
        // 包内文本/配置类文件（限制大小与数量避免卡顿）
        let textExt = [".plist", ".json", ".js", ".html", ".htm", ".txt", ".conf", ".config", ".xml", ".properties", ".ini"]
        let sensExt = [".mobileprovision", ".entitlements"]
        var scanned = 0
        for e in zip.entries where !e.isDirectory {
            let lower = e.name.lowercased()
            let isText = textExt.contains { lower.hasSuffix($0) }
            let isSensExt = sensExt.contains { lower.hasSuffix($0) }
            if !isText && !isSensExt { continue }
            if e.uncompSize > 400_000 { continue }                 // 跳过过大文件
            if e.name.contains("Frameworks/") || e.name.contains("PlugIns/") { continue }
            guard let data = zip.read(e.name), data.count <= 400_000 else { continue }
            scanned += 1
            if scanned > 120 { break }
            let findings = AnalyzerStrings.scan(data, maxTotal: 500)
            let hits = sensitiveHits(findings)
            if !hits.isEmpty {
                let rel = e.name.replacingOccurrences(of: appDir, with: "")
                let sev: Severity = hits.contains { $0.contains("凭据") || $0.contains("私钥") || $0.contains("password") } ? .critical : .high
                audit.append(ResourceFinding(path: rel.isEmpty ? e.name : rel, severity: sev, findings: hits))
            }
        }
        return audit
    }

    /// 敏感命中描述
    private func sensitiveHits(_ findings: [StringFinding]) -> [String] {
        var hits = [String]()
        var seen = Set<String>()
        for f in findings.prefix(600) {
            var tag: String? = nil
            let lower = f.text.lowercased()
            if f.kind == "key" || lower.contains("password") || lower.contains("secret") || lower.contains("token") ||
               lower.contains("api_key") || lower.contains("bearer") || lower.contains("-----begin") || lower.contains("jwt") {
                tag = "疑似凭据：\(f.text.prefix(60))"
            } else if f.kind == "ip" && AnalyzerStrings.isPrivateIP(f.text) {
                tag = "内网IP：\(f.text)"
            } else if f.kind == "http" {
                tag = "明文HTTP：\(f.text.prefix(80))"
            } else if f.kind == "email" {
                tag = "邮箱：\(f.text)"
            } else if f.kind == "phone" {
                tag = "手机号：\(f.text)"
            } else if f.kind == "domain" && (lower.contains("upload") || lower.contains("track") || lower.contains("collect") || lower.contains("telemetry")) {
                tag = "可疑域名：\(f.text)"
            }
            if let t = tag, !seen.contains(f.text) {
                seen.insert(f.text)
                hits.append(t)
            }
            if hits.count >= 20 { break }
        }
        return hits
    }

    // MARK: - 图标提取

    private func extractIcon(zip: ZipReader, appDir: String, plist: PlistInfo) -> String? {
        // 优先按 CFBundleIcons 指定的 PNG；否则取 .app 根目录最大的 PNG
        var candidates = [String]()
        let iconNames = plist.rawKeys["CFBundleIcons"] == nil ? [] : [String]()
        _ = iconNames
        for e in zip.entries where !e.isDirectory && e.name.hasPrefix(appDir) {
            let name = e.name
            guard name.lowercased().hasSuffix(".png") else { continue }
            let rel = String(name.dropFirst(appDir.count))
            // 跳过 Assets.car 内置与 Frameworks/PlugIns 内的图标
            if rel.hasPrefix("Frameworks/") || rel.hasPrefix("PlugIns/") || rel.contains("/") { continue }
            if rel.lowercased().contains("icon") || rel.lowercased().hasPrefix("appicon") {
                candidates.append(name)
            } else if e.uncompSize > 50_000 {
                candidates.append(name)
            }
        }
        // 挑最大
        var best: String?
        var bestSize = 0
        for c in candidates {
            if let e = zip.find(c), e.uncompSize > bestSize {
                bestSize = e.uncompSize; best = c
            }
        }
        guard let path = best, let data = zip.read(path), data.count > 100 else { return nil }
        return data.base64EncodedString()
    }
}
