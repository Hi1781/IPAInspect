import Foundation

/// 静态风险检测引擎：权限、ATS、URL/IP、可疑字符串、依赖等规则 → 打分 + 分级
enum AnalyzerRisk {

    static func evaluate(plist: PlistInfo, machO: MachOInfo,
                         strings: [StringFinding], credentials: [CredentialFinding],
                         resources: [ResourceFinding], urls: [URLFinding],
                         deps: [DependencyInfo]) -> (findings: [RiskFinding], score: Int) {
        var findings = [RiskFinding]()
        var score = 0

        // ---- 权限风险（声明本身仅低风险，须结合证据才升级）----
        let highPerms = plist.permissions.filter { $0.highRisk }
        let hasExfil = credentials.contains { $0.severity.rawValue >= 3 }
            || urls.contains { $0.kind != "https" }
            || strings.contains { $0.text.lowercased().contains("upload") }
            || resources.contains { $0.severity.rawValue >= 3 }
        if !highPerms.isEmpty {
            for p in highPerms {
                // 单条声明：仅低风险（避免“有权限就高危”）
                let isSensitive = ["NSCameraUsageDescription", "NSMicrophoneUsageDescription",
                                   "NSPhotoLibraryUsageDescription", "NSContactsUsageDescription",
                                   "NSLocationAlwaysUsageDescription", "NSLocalNetworkUsageDescription"].contains(p.key)
                let points = isSensitive ? 4 : 2
                let level: RiskLevel = isSensitive ? .low : .safe
                findings.append(RiskFinding(
                    title: "声明敏感权限：\(p.title)",
                    detail: p.detail + (hasExfil ? "；且检测到数据外传迹象（上传/非HTTPS外链/凭据），风险升级" : "（单独声明本身不必然恶意，需结合行为判断）"),
                    source: p.key,
                    points: points,
                    level: level,
                    suggestion: "结合是否存在数据外传逻辑综合判断；勒索木马常滥用相册/通讯录/麦克风权限"))
                score += points
            }
            // 权限 + 数据外传证据 → 升级
            if !highPerms.isEmpty && hasExfil {
                let names = highPerms.map { $0.title }.joined(separator: "、")
                findings.append(RiskFinding(
                    title: "敏感权限 + 数据外传迹象",
                    detail: "同时声明 \(names) 且存在上传/非HTTPS外链/硬编码凭据等证据，符合窃取型特征",
                    source: "权限 + 行为证据",
                    points: 18,
                    level: .suspicious,
                    suggestion: "重点核验是否存在窃取并回传个人信息的恶意行为"))
                score += 18
            }
            if highPerms.count >= 4 {
                let names = highPerms.map { $0.title }.joined(separator: "、")
                findings.append(RiskFinding(
                    title: "异常高危权限堆叠",
                    detail: "同时申请 \(names) 等 4 个以上隐私权限，申请面异常宽泛",
                    source: "权限组合",
                    points: 12,
                    level: .suspicious,
                    suggestion: "核验权限申请是否远超功能所需"))
                score += 12
            }
        }

        // ---- 凭据 / 硬编码密码 ----
        if !credentials.isEmpty {
            let critical = credentials.filter { $0.severity == .critical }
            let high = credentials.filter { $0.severity == .high }
            if !critical.isEmpty {
                findings.append(RiskFinding(
                    title: "发现硬编码私钥/机密",
                    detail: "提取到 \(critical.count) 条高危凭据（私钥/JWT/Secret 等）：\(critical.prefix(3).map { $0.text.prefix(40) }.joined(separator: "、"))",
                    source: "凭据扫描",
                    points: 24,
                    level: .malicious,
                    suggestion: "硬编码密钥一旦泄露即不可信，需立即轮换"))
                score += 24
            } else if !high.isEmpty {
                findings.append(RiskFinding(
                    title: "发现硬编码密码/令牌",
                    detail: "提取到 \(high.count) 条高危险级凭据（密码/API Key/Token 等），\(high.prefix(3).map { $0.text.prefix(30) }.joined(separator: "、"))",
                    source: "凭据扫描",
                    points: 14,
                    level: .suspicious,
                    suggestion: "应将凭据放入后端或钥匙串，不应硬编码在客户端"))
                score += 14
            } else {
                findings.append(RiskFinding(
                    title: "存在疑似凭据字符串",
                    detail: "提取到 \(credentials.count) 条疑似凭据，需人工核验",
                    source: "凭据扫描",
                    points: 6,
                    level: .low,
                    suggestion: "逐一核验是否真为敏感凭据"))
                score += 6
            }
        }

        // ---- 内容审查（多文件）----
        let criticalFiles = resources.filter { $0.severity == .critical }
        let highFiles = resources.filter { $0.severity == .high }
        if !criticalFiles.isEmpty {
            let names = criticalFiles.map { $0.path }.joined(separator: "、")
            findings.append(RiskFinding(
                title: "配置文件暴露高危机密",
                detail: "以下文件含私钥/密码等机密：\(names)",
                source: "内容审查",
                points: 22,
                level: .malicious,
                suggestion: "立即处理暴露的机密"))
            score += 22
        } else if !highFiles.isEmpty {
            let names = highFiles.prefix(4).map { $0.path }.joined(separator: "、")
            findings.append(RiskFinding(
                title: "资源文件含敏感信息",
                detail: "\(names) 等 \(highFiles.count) 个文件含凭据/内网IP/明文HTTP等敏感内容",
                source: "内容审查",
                points: 12,
                level: .suspicious,
                suggestion: "核验这些敏感信息是否应出现在客户端包内"))
            score += 12
        }

        // ---- ATS 明文传输 ----
        if plist.atsAllowsArbitraryLoads {
            findings.append(RiskFinding(
                title: "关闭 ATS 允许明文 HTTP",
                detail: "NSAppTransportSecurity 全局允许任意加载，通信可能以明文 HTTP 传输，可被中间人窃听",
                source: "NSAllowsArbitraryLoads",
                points: 16,
                level: .suspicious,
                suggestion: "应启用 HTTPS 并收紧 ATS 例外域名"))
            score += 16
        }
        if !plist.atsExceptions.isEmpty {
            findings.append(RiskFinding(
                title: "ATS 例外域名",
                detail: "存在 \(plist.atsExceptions.count) 个 ATS 例外域名：\(plist.atsExceptions.joined(separator: ", "))",
                source: "NSExceptionDomains",
                points: 4,
                level: .low,
                suggestion: "核验例外域名是否为自有受信服务"))
            score += 4
        }

        // ---- URL Scheme ----
        if plist.urlSchemes.count > 3 {
            findings.append(RiskFinding(
                title: "注册较多 URL Scheme",
                detail: "注册 \(plist.urlSchemes.count) 个自定义协议，可被外部 App 唤起",
                source: plist.urlSchemes.joined(separator: ", "),
                points: 4,
                level: .low,
                suggestion: "核验 URL Scheme 处理逻辑是否做了来源校验"))
            score += 4
        }

        // ---- 加密标记 ----
        if machO.encrypted {
            findings.append(RiskFinding(
                title: "Mach-O 已加密（FairPlay）",
                detail: "主程序带 LC_ENCRYPTION_INFO 加密标记，通常为 App Store 分发；无法进一步解析内部字符串与符号",
                source: "LC_ENCRYPTION_INFO",
                points: 0,
                level: .safe,
                suggestion: "若为 App Store 下载的加密包，请使用开发者导出的未加密 IPA 获取完整分析"))
        }

        // ---- 字符串 / URL 风险 ----
        let extURLs = urls.filter { $0.kind != "https" }
        let privateIPs = urls.filter { AnalyzerStrings.isPrivateIP($0.url) }
        if !privateIPs.isEmpty {
            findings.append(RiskFinding(
                title: "内网/保留 IP 直连",
                detail: "提取到 \(privateIPs.count) 个内网 IP：\(privateIPs.prefix(5).map { $0.url }.joined(separator: ", "))",
                source: "字符串扫描",
                points: 14,
                level: .suspicious,
                suggestion: "内网直连常见于恶意回传，需核验"))
            score += 14
        }
        if extURLs.count > 0 {
            findings.append(RiskFinding(
                title: "非 HTTPS 外链",
                detail: "存在 \(extURLs.count) 个明文/非 https 链接，可能与明文数据外传相关",
                source: "字符串扫描",
                points: 8,
                level: .suspicious,
                suggestion: "核验这些链接是否为自有受信服务且走 HTTPS"))
            score += 8
        }

        // 可疑关键词字符串
        let suspiciousWords = ["/api/", "upload", "login", "token", "secret", "password",
                               "admin", "callback", "webhook", "log", "track", "collect"]
        var kwHits = [String]()
        for s in strings {
            let lower = s.text.lowercased()
            if lower.count < 5 { continue }
            for kw in suspiciousWords where lower.contains(kw) {
                kwHits.append(s.text)
                break
            }
        }
        if kwHits.count > 10 {
            findings.append(RiskFinding(
                title: "含敏感关键词字符串较多",
                detail: "扫描到 \(kwHits.count) 条含 upload/login/token/secret 等关键词的字符串",
                source: "字符串扫描",
                points: 8,
                level: .suspicious,
                suggestion: "重点核验是否有数据上传、账号密码处理逻辑"))
            score += 8
        }

        // ---- 后台常驻模式 ----
        let bgModes = plist.backgroundModes
        if bgModes.contains("audio") || bgModes.contains("voip") {
            findings.append(RiskFinding(
                title: "后台常驻模式（\(bgModes.joined(separator: "/"))）",
                detail: "App 声明后台 audio/voip 模式，可后台长时间运行，配合录音/上传存在窃听风险",
                source: "UIBackgroundModes",
                points: 10,
                level: .suspicious,
                suggestion: "核验后台运行用途是否必要"))
            score += 10
        }

        // ---- 危险 URL Scheme ----
        let dangerSchemes = plist.urlSchemes.filter { ["tel", "sms", "mailto", "facetime", "itms", "itms-apps"].contains($0.lowercased()) }
        if !dangerSchemes.isEmpty {
            findings.append(RiskFinding(
                title: "注册可唤起通信类 Scheme",
                detail: "注册了 \(dangerSchemes.joined(separator: ", ")) 等协议，可诱导拨号/发短信/发邮件",
                source: "CFBundleURLTypes",
                points: 5,
                level: .low,
                suggestion: "核验是否存在诈骗诱导场景"))
            score += 5
        }

        // ---- 广告追踪 ----
        let hasTracking = plist.permissions.contains { $0.key == "NSUserTrackingUsageDescription" }
        let hasAdSupport = deps.contains { $0.name == "AdSupport" || $0.name.contains("Advert") }
        if hasTracking || hasAdSupport {
            findings.append(RiskFinding(
                title: "广告追踪（IDFA）",
                detail: hasTracking ? "声明用户追踪权限，可跨 App 追踪用户行为" : "集成 AdSupport 广告追踪库",
                source: hasTracking ? "NSUserTrackingUsageDescription" : "AdSupport",
                points: 6,
                level: .low,
                suggestion: "核验是否仅用于合规广告归因"))
            score += 6
        }

        // ---- 本地网络 ----
        if plist.permissions.contains(where: { $0.key == "NSLocalNetworkUsageDescription" }) {
            findings.append(RiskFinding(
                title: "本地网络访问",
                detail: "申请访问本地局域网，可用于局域网扫描、设备发现，或结合其他权限发起内网攻击",
                source: "NSLocalNetworkUsageDescription",
                points: 12,
                level: .suspicious,
                suggestion: "核验局域网访问用途，警惕内网渗透"))
            score += 12
        }

        // ---- 硬编码手机号 ----
        let phoneCount = strings.filter { $0.kind == "phone" }.count
        if phoneCount >= 3 {
            findings.append(RiskFinding(
                title: "含较多硬编码手机号",
                detail: "扫描到 \(phoneCount) 个手机号格式字符串，可能用于诈骗/短信轰炸",
                source: "字符串扫描",
                points: 6,
                level: .low,
                suggestion: "核验这些号码的用途"))
            score += 6
        }

        // ---- 蓝牙 + 定位组合 ----
        let hasBT = plist.permissions.contains { $0.key == "NSBluetoothAlwaysUsageDescription" }
        let hasLoc = plist.permissions.contains { $0.key.hasPrefix("NSLocation") }
        if hasBT && hasLoc {
            findings.append(RiskFinding(
                title: "蓝牙+定位组合",
                detail: "同时申请蓝牙与定位权限，符合近距离跟踪/信标定位特征",
                source: "权限组合",
                points: 14,
                level: .suspicious,
                suggestion: "警惕近距离跟踪场景"))
            score += 14
        }

        // ---- 依赖库风险 ----
        for dep in deps where dep.kind == "thirdparty" && dep.note.contains("逆向") {
            findings.append(RiskFinding(
                title: "集成逆向相关库",
                detail: "检测到第三方库 \(dep.name)（\(dep.note)）",
                source: dep.name,
                points: 12,
                level: .suspicious,
                suggestion: "核验库来源与用途"))
            score += 12
        }

        // ---- 弱加密/签名缺失等 ----
        if !machO.hasCodeSignature {
            findings.append(RiskFinding(
                title: "缺少代码签名槽",
                detail: "主程序无 LC_CODE_SIGNATURE，为未签名/原始包，无法验证来源完整性",
                source: "LC_CODE_SIGNATURE",
                points: 6,
                level: .low,
                suggestion: "核验包来源，正式分发应带有效签名"))
            score += 6
        }

        // 存在恶意组合时提高总分
        let hasUpload = strings.contains { $0.text.lowercased().contains("upload") }
        let hasCam = plist.permissions.contains { $0.key == "NSCameraUsageDescription" }
        let hasLib = plist.permissions.contains { $0.key == "NSPhotoLibraryUsageDescription" }
        if hasCam && hasUpload {
            findings.append(RiskFinding(
                title: "相机+上传组合",
                detail: "同时申请相机权限且存在 upload 相关字符串，符合录屏/勒索类特征",
                source: "权限+字符串",
                points: 18,
                level: .malicious,
                suggestion: "高度警惕录屏勒索、拍摄勒索行为"))
            score += 18
        }
        if hasCam && hasLib && !extURLs.isEmpty {
            findings.append(RiskFinding(
                title: "媒体窃取组合",
                detail: "相机+相册+非 HTTPS 外链并存，符合窃取照片并回传的勒索木马特征",
                source: "权限+URL",
                points: 22,
                level: .malicious,
                suggestion: "立即核验是否存在照片/视频窃取与回传"))
            score += 22
        }

        // ---- 命令执行能力 ----
        let cmdWords = ["system(", "popen(", "exec(", "/bin/sh", "/bin/bash", "NSAppleScript",
                        "osascript", "NSTask", "Process("]
        let cmdHits = strings.filter { t in
            let l = t.text.lowercased()
            return cmdWords.contains(where: { l.contains($0.lowercased()) })
        }
        if !cmdHits.isEmpty {
            findings.append(RiskFinding(
                title: "具备命令执行能力",
                detail: "字符串含 system/popen/NSTask/osascript 等 \(cmdHits.count) 处调用，可在设备上执行系统命令",
                source: cmdHits.prefix(3).map { $0.text }.joined(separator: "、"),
                points: 16,
                level: .suspicious,
                suggestion: "合法 App 极少调用系统命令，需核验是否存在命令注入/下载执行"))
            score += 16
        }

        // ---- WebView 动态注入 ----
        let hasWebKit = deps.contains { $0.name == "WebKit" || $0.name == "JavaScriptCore" }
        let injectWords = ["loadHTMLString", "evaluateJavaScript", "URLSchemeHandler",
                           "javascript:", "WKUserContentController"]
        let injectHits = strings.filter { t in
            let l = t.text.lowercased()
            return injectWords.contains(where: { l.contains($0.lowercased()) })
        }
        if hasWebKit && !injectHits.isEmpty {
            findings.append(RiskFinding(
                title: "WebView 动态内容注入",
                detail: "集成 WebKit 且存在 loadHTMLString/evaluateJavaScript 等 \(injectHits.count) 处，可加载远程内容执行 JS",
                source: "WebKit + 注入字符串",
                points: 10,
                level: .suspicious,
                suggestion: "若加载远程页面并注入本地数据，存在钓鱼/数据外泄面"))
            score += 10
        }

        // ---- 剪贴板读取 ----
        let pasteHits = strings.filter { $0.text.lowercased().contains("pasteboard") }
        if !pasteHits.isEmpty {
            findings.append(RiskFinding(
                title: "访问系统剪贴板",
                detail: "引用 UIPasteboard/generalPasteboard 等 \(pasteHits.count) 处，可静默读取用户复制的敏感内容",
                source: "UIPasteboard",
                points: 8,
                level: .suspicious,
                suggestion: "剪贴板窃取常用于窃取验证码/助记词，需重点核验"))
            score += 8
        }

        // ---- C2 / 高风险外联域名 ----
        let c2Kws = [".onion", "t.me", "telegram", "discord", "pastebin", "paste.ee",
                     "bit.ly", "tinyurl", "raw.githubusercontent", "dropbox", "s3.amazonaws"]
        let c2URLs = urls.filter { u in c2Kws.contains(where: { u.url.lowercased().contains($0) }) }
        if !c2URLs.isEmpty {
            findings.append(RiskFinding(
                title: "疑似 C2 / 分发外联",
                detail: "提取到 \(c2URLs.count) 个暗网/Telegram/临时网盘/裸 Gist 类地址：\(c2URLs.prefix(4).map { $0.url }.joined(separator: "、"))",
                source: "字符串扫描",
                points: 16,
                level: .suspicious,
                suggestion: "此类地址常用于木马指令下发或样本分发，需高度警惕"))
            score += 16
        }

        // ---- 长 Base64 编码隐藏串 ----
        let b64Hits = strings.filter { s in
            let t = s.text.trimmingCharacters(in: .whitespaces)
            guard t.count >= 40 else { return false }
            let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            if t.rangeOfCharacter(from: allowed.inverted) != nil { return false }
            return t.count % 4 == 0 && t.contains("=")
        }
        if b64Hits.count >= 2 {
            findings.append(RiskFinding(
                title: "疑似编码后的隐藏配置",
                detail: "扫描到 \(b64Hits.count) 条长 Base64 字符串，可能是编码后的命令/域名/载荷",
                source: "字符串扫描",
                points: 10,
                level: .suspicious,
                suggestion: "解码核验是否隐藏指令下发或回传地址"))
            score += 10
        }

        // ---- Bundle ID 泛化 / 伪签特征 ----
        let bid = plist.bundleID.lowercased()
        if bid.contains("com.example") || bid.contains("org.template") || bid.contains(".test") ||
           bid.contains("debug") || bid.isEmpty {
            findings.append(RiskFinding(
                title: "Bundle ID 泛化/未上线特征",
                detail: "Bundle ID「\(plist.bundleID)」为示例/测试样式，通常非正式上架 App",
                source: "CFBundleIdentifier",
                points: 4,
                level: .low,
                suggestion: "常见于演示包或改装包，核验来源"))
            score += 4
        }

        // ---- 权限面过宽 ----
        if plist.permissions.count >= 8 {
            findings.append(RiskFinding(
                title: "权限申请面过宽",
                detail: "共申请 \(plist.permissions.count) 项权限，明显超出常见功能所需",
                source: "权限集合",
                points: 8,
                level: .suspicious,
                suggestion: "权限面越宽，数据窃取/攻击面越大，需重点核验"))
            score += 8
        }

        // ---- 最低系统版本过低 ----
        if !plist.minOS.isEmpty, plist.minOS.compare("12.0", options: .numeric) == .orderedAscending {
            findings.append(RiskFinding(
                title: "最低系统版本过低",
                detail: "支持 iOS \(plist.minOS) 及以上，可在大量老旧设备运行，扩大潜在攻击范围",
                source: "MinimumOSVersion",
                points: 2,
                level: .low,
                suggestion: "通常不影响判定，仅提示受众面"))
            score += 2
        }

        // ---- 病毒审查库（恶意特征签名）----
        let malware = AnalyzerMalware.scan(strings: strings)
        for m in malware {
            findings.append(m)
            score += m.points
        }

        let capped = min(score, 100)
        return (findings.sorted { $0.points > $1.points }, capped)
    }

    /// 权限分布统计（用于饼图）
    static func permissionDistribution(_ plist: PlistInfo) -> (high: Int, normal: Int) {
        let high = plist.permissions.filter { $0.highRisk }.count
        let normal = plist.permissions.filter { !$0.highRisk }.count
        return (high, normal)
    }
}
