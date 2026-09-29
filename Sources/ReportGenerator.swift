import Foundation

/// 概览页「综合文字描述报告」生成器：把分析结果凝练成一段连贯的中文报告。
enum ReportGenerator {

    static func summary(_ r: AnalysisResult) -> String {
        var s = ""
        // 引言与包信息
        let name = r.plist.displayName.isEmpty ? r.fileName : r.plist.displayName
        s += "对「\(name)」（\(r.plist.bundleID.isEmpty ? "未知 Bundle ID" : r.plist.bundleID)\(r.plist.shortVersion.isEmpty ? "" : " v\(r.plist.shortVersion)")，\(r.fileCount) 个文件/\(r.directoryCount) 个目录）的离线静态分析得出综合结论：风险评分 \(r.score)/100，判定为「\(r.riskLevel.label)」。"

        // 权限态势
        let perms = r.plist.permissions
        if perms.isEmpty {
            s += " 该应用未声明任何 iOS 隐私权限，权限面干净。"
        } else {
            let high = perms.filter { $0.highRisk }.count
            s += " 权限方面共申请 \(perms.count) 项，其中敏感权限 \(high) 项（如\(perms.filter { $0.highRisk }.prefix(4).map { $0.title }.joined(separator: "、"))），权限面\(high >= 4 ? "明显偏宽" : "总体可控")。"
        }

        // 网络与凭据
        let ext = r.urls.filter { $0.kind != "https" }
        let creds = r.credentials ?? []
        var netParts = [String]()
        if !r.urls.isEmpty { netParts.append("提取到 \(r.urls.count) 个网络端点") }
        if !ext.isEmpty { netParts.append("其中 \(ext.count) 个为非 HTTPS/明文（存在中间人窃听与明文外传风险）") }
        if let prv = r.urls.filter({ AnalyzerStrings.isPrivateIP($0.url) }).first?.url { netParts.append("存在内网 IP（\(prv)）直连迹象") }
        if !netParts.isEmpty { s += " 网络侧，\(netParts.joined(separator: "；"))。" }
        if !creds.isEmpty {
            let c = creds.filter { $0.severity.rawValue >= 3 }.count
            s += " 更关键的是，硬编码了 \(creds.count) 条疑似凭据（其中高危机密 \(c) 条），一旦外传即构成真实数据泄漏。"
        }

        // 病毒审查库命中
        let malware = AnalyzerMalware.scan(strings: r.strings)
        if !malware.isEmpty {
            s += " 病毒审查库命中 \(malware.count) 类恶意特征（\(malware.map { $0.title }.joined(separator: "、"))）。"
        }
        if let c2 = AnalyzerMalware.scanC2(urls: r.urls, strings: r.strings) {
            s += " 此外与已知 C2 基础设施（外部 IOC 库）关联，属高危信号。"
        }

        // 动态模拟
        let simScore = DynamicSimulator.simulatedScore(r)
        if simScore.points != r.score {
            s += " 计入模拟运行行为后综合评分约 \(simScore.points)/100（\(simScore.verdict)）。"
        }

        // 签名状态
        if let sig = r.signing, sig.hasProfile {
            s += " 包内含签名配置（Team \(sig.teamIdentifier.isEmpty ? "-" : sig.teamIdentifier)，有效期至 \(sig.expirationDate.isEmpty ? "-" : sig.expirationDate)）。"
        } else {
            s += " 包内未含 embedded.mobileprovision，来源完整性无法验证。"
        }

        // 结论句
        s += " 综合以上证据，该样本\(r.riskLevel == .malicious ? "具有明显恶意特征，建议隔离并在受控环境进一步动态验证" : r.riskLevel == .suspicious ? "存在多处可疑迹象，建议谨慎对待并深入核验" : r.riskLevel == .low ? "风险总体较低，可酌情使用，仍建议关注敏感权限" : "未发现明显风险，可正常使用")。"
        return s
    }
}
