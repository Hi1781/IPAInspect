import Foundation

/// 动态分析模拟器：基于静态证据生成「模拟运行时行为轨迹」。
/// 真实 hook 需越狱 + frida，无法在裸 IPA 沙盒内运行；此模块在设备内模拟
/// 一次典型运行的行为事件流与模拟判定，供用户直观预览动态分析产出。
enum DynamicSimulator {
    struct Event {
        let time: String
        let tag: String
        let detail: String
        let sev: Severity
    }

    static func simulate(_ r: AnalysisResult) -> [Event] {
        var ev = [Event]()
        let perms = r.plist.permissions

        ev.append(Event(time: "0.0s", tag: "LAUNCH", detail: "启动主程序，加载依赖库", sev: .safe))
        if !r.plist.urlSchemes.isEmpty {
            ev.append(Event(time: "0.3s", tag: "SCHEME", detail: "注册 URL Scheme：\(r.plist.urlSchemes.joined(separator: ", "))", sev: .low))
        }

        var t: Double = 0.6
        func push(_ tag: String, _ d: String, _ s: Severity) {
            ev.append(Event(time: String(format: "%.1fs", t), tag: tag, detail: d, sev: s))
            t += 0.3
        }

        for p in perms {
            switch p.key {
            case "NSCameraUsageDescription": push("CAM", "申请相机权限 → 授予", .high)
            case "NSMicrophoneUsageDescription": push("MIC", "申请麦克风权限 → 授予", .high)
            case "NSPhotoLibraryUsageDescription": push("PHOTO", "申请相册权限 → 授予", .high)
            case "NSContactsUsageDescription": push("CONTACTS", "读取通讯录 CNContactStore", .high)
            case "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysUsageDescription":
                push("LOC", "CLLocationManager 启动定位", .high)
            case "NSLocalNetworkUsageDescription": push("LAN", "NWBrowser 扫描本地网络", .high)
            default: break
            }
        }

        let ext = r.urls.filter { $0.kind != "https" }
        if let first = ext.first {
            push("NET", "NSURLSession 明文请求 → \(first.url)", .high)
        }
        if let cred = (r.credentials ?? []).first(where: { $0.severity.rawValue >= 3 }) {
            push("LEAK", "上传请求体包含凭据「\(cred.text.prefix(24))」", .critical)
        }
        if r.strings.contains(where: { $0.text.lowercased().contains("pasteboard") }) {
            push("CLIP", "读取系统剪贴板 UIPasteboard", .high)
        }
        if !r.plist.backgroundModes.isEmpty {
            push("BG", "进入后台常驻：\(r.plist.backgroundModes.joined(separator: "/"))", .high)
        }
        if !AnalyzerMalware.scan(strings: r.strings).isEmpty {
            push("C2", "检测到恶意特征信号，发送 keepalive 心跳", .critical)
        }
        ev.append(Event(time: String(format: "%.1fs", t), tag: "END", detail: "模拟运行结束（真实运行需 frida/mitmproxy 采集）", sev: .safe))
        return ev
    }

    static func simulatedScore(_ r: AnalysisResult) -> (points: Int, verdict: String) {
        let highCount = simulate(r).filter { $0.sev.rawValue >= 3 }.count
        let points = min(r.score + highCount * 2, 100)
        let verdict: String
        if points >= 75 { verdict = "恶意" }
        else if points >= 45 { verdict = "可疑" }
        else if points >= 20 { verdict = "低风险" }
        else { verdict = "安全" }
        return (points, verdict)
    }
}
