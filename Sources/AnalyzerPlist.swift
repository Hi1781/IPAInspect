import Foundation

/// Info.plist / embedded.mobileprovision 解析
enum AnalyzerPlist {

    static func parse(_ data: Data) -> PlistInfo? {
        guard let obj = propertyList(data) as? [String: Any] else { return nil }
        var info = PlistInfo.empty

        info.bundleID = str(obj["CFBundleIdentifier"])
        info.displayName = str(obj["CFBundleDisplayName"])
        info.name = str(obj["CFBundleName"])
        info.shortVersion = str(obj["CFBundleShortVersionString"])
        info.buildVersion = str(obj["CFBundleVersion"])
        info.minOS = str(obj["MinimumOSVersion"])

        if let fam = obj["UIDeviceFamily"] as? [Any] {
            info.deviceFamily = fam.compactMap { ($0 as? Int).map { $0 == 1 ? "iPhone" : ($0 == 2 ? "iPad" : "\($0)") } }
        }
        if let plat = obj["CFBundleSupportedPlatforms"] as? [Any] {
            info.supportedPlatforms = plat.compactMap { $0 as? String }
        }
        if let urlTypes = obj["CFBundleURLTypes"] as? [[String: Any]] {
            var schemes = [String]()
            for t in urlTypes {
                if let s = t["CFBundleURLSchemes"] as? [Any] {
                    for x in s {
                        if let str = x as? String, !schemes.contains(str) { schemes.append(str) }
                    }
                }
            }
            info.urlSchemes = schemes
        }
        if let bm = obj["UIBackgroundModes"] as? [Any] {
            info.backgroundModes = bm.compactMap { $0 as? String }
        }
        if let ats = obj["NSAppTransportSecurity"] as? [String: Any] {
            info.atsAllowsArbitraryLoads = bool(ats["NSAllowsArbitraryLoads"])
            if let ex = ats["NSExceptionDomains"] as? [String: Any] {
                info.atsExceptions = ex.keys.sorted()
            }
        }
        if let loc = obj["CFBundleLocalizations"] as? [Any] {
            info.localizations = loc.compactMap { $0 as? String }
        } else if let dev = str(obj["CFBundleDevelopmentRegion"]) as String?, !dev.isEmpty {
            info.localizations = [dev]
        }

        // 权限
        info.permissions = extractPermissions(obj)

        // 扁平化原始键
        var raw: [String: String] = [:]
        for (k, v) in obj {
            if let s = v as? String { raw[k] = s }
            else if let b = v as? Bool { raw[k] = b ? "true" : "false" }
            else if let i = v as? Int { raw[k] = "\(i)" }
            else if let a = v as? [Any] { raw[k] = a.map { "\($0)" }.joined(separator: ", ") }
            else if let d = v as? [String: Any] { raw[k] = "<dict \(d.count)>" }
        }
        info.rawKeys = raw
        return info
    }

    // MARK: - 权限提取

    private static let highRiskPermissions: [String: (String, String)] = [
        "NSCameraUsageDescription": ("相机", "可调用设备摄像头拍照/录像，恶意应用可用于偷拍、录制勒索视频"),
        "NSPhotoLibraryUsageDescription": ("相册", "可读取设备相册中的图片与视频，恶意应用可窃取并上传个人私密照片"),
        "NSPhotoLibraryAddUsageDescription": ("保存相册", "可向相册写入图片/视频，用于保存被诱导录制的勒索内容"),
        "NSMicrophoneUsageDescription": ("麦克风", "可录制音频，恶意应用可窃听或录制勒索视频"),
        "NSLocationWhenInUseUsageDescription": ("定位(前台)", "可获取实时位置，用于跟踪用户行踪"),
        "NSLocationAlwaysUsageDescription": ("定位(常驻)", "可后台持续获取位置，跟踪行踪"),
        "NSLocationAlwaysAndWhenInUseUsageDescription": ("定位(始终)", "后台持续获取位置，跟踪行踪"),
        "NSContactsUsageDescription": ("通讯录", "可读取通讯录，勒索木马常窃取联系人并威胁群发"),
        "NSCalendarsUsageDescription": ("日历", "可读取日历日程，泄露行程"),
        "NSRemindersUsageDescription": ("提醒事项", "可读取提醒事项，泄露隐私"),
        "NSMotionUsageDescription": ("运动与健身", "可读取运动数据"),
        "NSBluetoothAlwaysUsageDescription": ("蓝牙(始终)", "可后台扫描/连接蓝牙设备"),
        "NSBluetoothPeripheralUsageDescription": ("蓝牙(外设)", "可连接/扫描蓝牙外设，用于跟踪设备"),
        "NSLocalNetworkUsageDescription": ("本地网络", "可访问本地局域网，用于局域网扫描、投屏/传文件劫持"),
        "NSSpeechRecognitionUsageDescription": ("语音识别", "可上传语音进行识别，泄露谈话内容"),
        "NSFaceIDUsageDescription": ("面容ID", "可调用生物识别，需警惕滥用"),
        "NSUserTrackingUsageDescription": ("用户追踪", "可跨App追踪用户行为用于广告"),
        "NSHealthShareUsageDescription": ("健康数据", "可读取健康与健身数据"),
        "NSHealthUpdateUsageDescription": ("健康写入", "可写入健康数据"),
        "NSSystemAdministrationUsageDescription": ("系统管理", "可进行系统级管理操作，权限过高需警惕"),
        "NSAppleEventsUsageDescription": ("Apple事件", "可向其他App发送Apple事件，自动化操作"),
        "NSFileProviderPresenceUsageDescription": ("文件提供者", "可常驻管理文件，需警惕数据外传"),
    ]

    private static func extractPermissions(_ obj: [String: Any]) -> [PermissionInfo] {
        var perms = [PermissionInfo]()
        for (key, value) in obj {
            guard let hr = highRiskPermissions[key] else { continue }
            let desc = (value as? String) ?? ""
            perms.append(PermissionInfo(key: key, title: hr.0,
                                        detail: desc.isEmpty ? hr.1 : desc,
                                        highRisk: true))
        }
        // 加入少量非高危但值得记录的配置
        let extra: [(String, String, String)] = [
            ("NSAppleMusicUsageDescription", "媒体资料库", "可读取媒体库资料"),
            ("NSSiriUsageDescription", "Siri", "与 Siri 集成"),
            ("NSHomeKitUsageDescription", "HomeKit", "可访问智能家居数据"),
            ("NFCReaderUsageDescription", "NFC", "可读取 NFC 标签"),
            ("NSUserNotificationsUsageDescription", "通知", "可发送本地通知"),
            ("NSWidgetKitUsageDescription", "小组件", "可运行桌面小组件"),
        ]
        for (key, title, desc) in extra {
            if obj[key] != nil {
                perms.append(PermissionInfo(key: key, title: title,
                                            detail: (obj[key] as? String) ?? desc, highRisk: false))
            }
        }
        return perms.sorted { $0.key < $1.key }
    }

    // MARK: - embedded.mobileprovision 解析

    /// 从 mobileprovision（DER 封装内嵌 Plist XML）中提取签名信息。
    /// 采用正则扫描 key/value 对，兼容 binary 与 XML 两种封装。
    static func parseProvisioning(_ data: Data) -> ProvisioningInfo {
        var info = ProvisioningInfo.empty
        let s = String(decoding: data, as: UTF8.self)
        guard !s.isEmpty else { return info }
        info.hasProfile = true

        func str(_ key: String) -> String {
            firstMatch(s, pattern: "<key>\(key)</key>\\s*<string>([^<]*)</string>") ?? ""
        }
        func intv(_ key: String) -> Int? {
            firstMatch(s, pattern: "<key>\(key)</key>\\s*<integer>([^<]*)</integer>").flatMap { Int($0) }
        }
        func date(_ key: String) -> String {
            guard let raw = firstMatch(s, pattern: "<key>\(key)</key>\\s*<date>([^<]*)</date>") else { return "" }
            if let d = iso.date(from: raw) {
                let out = DateFormatter()
                out.dateFormat = "yyyy-MM-dd HH:mm"
                return out.string(from: d)
            }
            return raw
        }
        func array(_ key: String) -> [String] {
            guard let block = block(s, key: key) else { return [] }
            return allStrings(in: block)
        }

        info.appIDName = str("AppIDName")
        info.teamIdentifier = array("TeamIdentifier").joined(separator: "/")
        info.appIDPrefix = array("ApplicationIdentifierPrefix").joined(separator: "/")
        info.expirationDate = date("ExpirationDate")
        info.timeToLive = intv("TimeToLive") ?? 0
        info.provisionedDevices = array("ProvisionedDevices").count

        // Entitlements 字典 → 扁平化
        if let ent = entitlementsDict(s) {
            info.entitlements = ent
        }
        return info
    }

    /// 提取 Entitlements 的 <dict>…</dict> 块
    private static func entitlementsDict(_ s: String) -> [String: String]? {
        guard let k = s.range(of: "<key>Entitlements</key>") else { return nil }
        let tail = s[k.upperBound...]
        guard let dopen = tail.range(of: "<dict>"), let dclose = tail.range(of: "</dict>"),
              dopen.lowerBound < dclose.lowerBound else { return nil }
        return scanDict(tail[dopen.upperBound..<dclose.lowerBound])
    }

    private static let iso = ISO8601DateFormatter()

    /// 从整串中取 key 后紧跟的标量值块（下一个 <key> 或 </dict> 之前）
    private static func block(_ s: String, key: String) -> Substring? {
        guard let k = s.range(of: "<key>\(key)</key>") else { return nil }
        let tail = s[k.upperBound...]
        let end = tail.range(of: "<key>")?.lowerBound ?? tail.endIndex
        return tail[tail.startIndex..<end]
    }

    private static func allStrings(in sub: Substring) -> [String] {
        var res = [String]()
        var rest = sub
        while let open = rest.range(of: "<string>"), let close = rest.range(of: "</string>"),
              open.lowerBound < close.lowerBound {
            res.append(String(rest[open.upperBound..<close.lowerBound]))
            rest = rest[close.upperBound...]
        }
        return res
    }

    /// 扫描 dict 块内的 key/标量 对（只解析 key 后紧随的标签，避免错位）
    private static func scanDict(_ block: Substring) -> [String: String] {
        var out = [String: String]()
        var rest = block
        while let ko = rest.range(of: "<key>"), let kc = rest.range(of: "</key>"),
              ko.lowerBound < kc.lowerBound {
            let key = String(rest[ko.upperBound..<kc.lowerBound])
            var tail = rest[kc.upperBound...]
            tail = Substring(tail.drop(while: { $0 == "\n" || $0 == "\t" || $0 == " " || $0 == "\r" }))

            var val = ""
            var consumed = tail.startIndex
            if tail.hasPrefix("<true/>") {
                val = "true"; consumed = tail.index(tail.startIndex, offsetBy: 7)
            } else if tail.hasPrefix("<false/>") {
                val = "false"; consumed = tail.index(tail.startIndex, offsetBy: 8)
            } else if tail.hasPrefix("<string>") {
                if let sc = tail.range(of: "</string>") {
                    val = String(tail[tail.index(tail.startIndex, offsetBy: 8)..<sc.lowerBound])
                    consumed = tail.index(sc.lowerBound, offsetBy: 9)
                }
            } else if tail.hasPrefix("<integer>") {
                if let ic = tail.range(of: "</integer>") {
                    val = String(tail[tail.index(tail.startIndex, offsetBy: 9)..<ic.lowerBound])
                    consumed = tail.index(ic.lowerBound, offsetBy: 10)
                }
            } else if tail.hasPrefix("<date>") {
                if let dc = tail.range(of: "</date>") {
                    val = String(tail[tail.index(tail.startIndex, offsetBy: 6)..<dc.lowerBound])
                    consumed = tail.index(dc.lowerBound, offsetBy: 7)
                }
            } else if tail.hasPrefix("<array>") {
                if let ac = tail.range(of: "</array>") {
                    val = allStrings(in: tail[tail.index(tail.startIndex, offsetBy: 7)..<ac.lowerBound]).joined(separator: ", ")
                    consumed = tail.index(ac.lowerBound, offsetBy: 8)
                }
            } else if tail.hasPrefix("<data>") {
                if let dc = tail.range(of: "</data>") {
                    val = "<data>"
                    consumed = tail.index(dc.lowerBound, offsetBy: 7)
                }
            } else if tail.hasPrefix("<dict>") {
                if let dc = tail.range(of: "</dict>") {
                    consumed = tail.index(dc.lowerBound, offsetBy: 7)
                }
            }
            out[key] = val
            rest = tail[consumed...]
        }
        return out
    }

    private static func firstMatch(_ s: String, pattern: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(s.startIndex..<s.endIndex, in: s)
        guard let m = re.firstMatch(in: s, range: range),
              m.numberOfRanges >= 2,
              let r = Range(m.range(at: 1), in: s) else { return nil }
        return String(s[r])
    }

    // MARK: - 通用

    private static func propertyList(_ data: Data) -> Any? {
        // 尝试 binary plist 与 XML
        var fmt = PropertyListSerialization.PropertyListFormat.xml
        let o1 = try? PropertyListSerialization.propertyList(from: data, options: [], format: &fmt)
        if o1 != nil { return o1 }
        // 若前面带签名数据头（mobileprovision 常为 DER 后跟 plist），尝试剥离
        if data.count > 100 {
            let body = data.dropFirst(max(0, data.count - 1_500_000))
            let o2 = try? PropertyListSerialization.propertyList(from: Data(body), options: [], format: &fmt)
            if o2 != nil { return o2 }
        }
        return nil
    }

    static func str(_ v: Any?) -> String {
        v as? String ?? ""
    }

    static func bool(_ v: Any?) -> Bool {
        v as? Bool ?? false
    }
}
