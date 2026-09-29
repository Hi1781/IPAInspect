import Foundation

/// 报告导出：Markdown / 纯文本
enum ReportExporter {

    static func markdown(_ r: AnalysisResult) -> String {
        var s = "# IPA 静态分析报告\n\n"
        s += "- 文件名：\(r.fileName)\n"
        s += "- 文件大小：\(UIThemeBytes(r.fileSize))\n"
        s += "- 分析时间：\(r.analyzedAt)\n"
        s += "- 风险等级：**\(r.riskLevel.label)**（评分 \(r.score)/100）\n\n"

        s += "## 哈希\n\n"
        s += "| 算法 | 值 |\n|---|---|\n"
        s += "| MD5 | \(r.md5) |\n"
        s += "| SHA1 | \(r.sha1) |\n"
        s += "| SHA256 | \(r.sha256) |\n"
        s += "| SHA512 | \(r.sha512) |\n\n"

        s += "## 基本信息\n\n"
        s += "- Bundle ID：\(r.plist.bundleID.isEmpty ? "-" : r.plist.bundleID)\n"
        s += "- 名称：\(r.plist.displayName.isEmpty ? r.plist.name : r.plist.displayName)\n"
        s += "- 版本：\(r.plist.shortVersion)（build \(r.plist.buildVersion)）\n"
        s += "- 最低系统：\(r.plist.minOS)\n"
        s += "- 架构：\(r.machO.architectures.joined(separator: ", "))\n"
        s += "- FairPlay 加密：\(r.machO.encrypted ? "是" : "否")\n\n"

        if !r.plist.permissions.isEmpty {
            s += "## 权限\n\n"
            for p in r.plist.permissions {
                s += "- \(p.highRisk ? "🔴" : "🔵") \(p.key)（\(p.title)）：\(p.detail)\n"
            }
            s += "\n"
        }

        if !r.plist.backgroundModes.isEmpty {
            s += "## 后台模式\n\n"
            s += "- " + r.plist.backgroundModes.joined(separator: ", ") + "\n\n"
        }

        if let sig = r.signing, sig.hasProfile {
            s += "## 签名证书\n\n"
            s += "- AppID 名称：\(sig.appIDName.isEmpty ? "-" : sig.appIDName)\n"
            s += "- Team ID：\(sig.teamIdentifier.isEmpty ? "-" : sig.teamIdentifier)\n"
            s += "- App ID 前缀：\(sig.appIDPrefix.isEmpty ? "-" : sig.appIDPrefix)\n"
            s += "- 有效期至：\(sig.expirationDate.isEmpty ? "-" : sig.expirationDate)\n"
            s += "- 注册设备数：\(sig.provisionedDevices)\n"
            if !sig.entitlements.isEmpty {
                s += "- Entitlements：\n"
                for e in sig.entitlements.sorted(by: { $0.key < $1.key }) {
                    s += "  - \(e.key) = \(e.value)\n"
                }
            }
            s += "\n"
        }

        if !r.urls.isEmpty {
            s += "## URL / IP / 域名\n\n"
            for u in r.urls.prefix(200) {
                s += "- \(u.url)\(u.suspicious ? "（⚠️可疑）" : "")\n"
            }
            s += "\n"
        }

        if let creds = r.credentials, !creds.isEmpty {
            s += "## 凭据 / 密码\n\n"
            for c in creds.prefix(200) {
                s += "- [\(c.severity.label)] \(c.type)：\(c.text.prefix(120))（\(c.source)）\n"
            }
            s += "\n"
        }

        if let audit = r.resourceAudit, !audit.isEmpty {
            s += "## 内容审查（多文件）\n\n"
            for a in audit.prefix(100) {
                s += "- **[\(a.severity.label)] \(a.path)**\n"
                for f in a.findings.prefix(20) {
                    s += "  - \(f)\n"
                }
            }
            s += "\n"
        }

        if !r.deps.isEmpty {
            s += "## 依赖库\n\n"
            for d in r.deps {
                s += "- \(d.name)（\(d.note)）\n"
            }
            s += "\n"
        }

        if !r.findings.isEmpty {
            s += "## 风险发现\n\n"
            for f in r.findings {
                s += "- **[\(f.level.label)] \(f.title)**（+\(f.points)分）\n"
                s += "  - 证据：\(f.source)\n"
                s += "  - 说明：\(f.detail)\n"
                s += "  - 建议：\(f.suggestion)\n"
            }
            s += "\n"
        }

        if let note = r.encryptionNote {
            s += "> 提示：\(note)\n"
        }
        return s
    }

    private static func UIThemeBytes(_ b: Int) -> String {
        let v = Double(b)
        if v >= 1_048_576 { return String(format: "%.2f MB", v / 1_048_576) }
        if v >= 1024 { return String(format: "%.1f KB", v / 1024) }
        return "\(b) B"
    }
}
