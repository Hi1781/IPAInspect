import Foundation

/// 静态风险检测引擎：权限、ATS、URL/IP、可疑字符串、依赖等规则 → 打分 + 分级
enum AnalyzerRisk {

    static func evaluate(plist: PlistInfo, machO: MachOInfo,
                         strings: [StringFinding], urls: [URLFinding],
                         deps: [DependencyInfo]) -> (findings: [RiskFinding], score: Int) {
        var findings = [RiskFinding]()
        var score = 0

        // ---- 权限风险 ----
        let highPerms = plist.permissions.filter { $0.highRisk }
        if !highPerms.isEmpty {
            for p in highPerms {
                findings.append(RiskFinding(
                    title: "敏感权限：\(p.title)",
                    detail: p.detail,
                    source: p.key,
                    points: 8,
                    level: .suspicious,
                    suggestion: "评估该权限是否与功能必要匹配；勒索木马常滥用相册/通讯录/麦克风权限"))
                score += 8
            }
            if highPerms.count >= 3 {
                let names = highPerms.map { $0.title }.joined(separator: "、")
                findings.append(RiskFinding(
                    title: "高危权限组合",
                    detail: "同时申请 \(names) 等多个隐私权限，符合窃取型木马特征",
                    source: "权限组合",
                    points: 20,
                    level: .malicious,
                    suggestion: "需重点核验是否存在窃取个人信息的恶意行为"))
                score += 20
            }
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
