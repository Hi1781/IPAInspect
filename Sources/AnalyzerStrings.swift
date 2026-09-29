import Foundation

/// 字符串扫描：从 Mach-O 二进制中提取可读字符串并分类
enum AnalyzerStrings {

    static func scan(_ data: Data, maxTotal: Int = 3000) -> [StringFinding] {
        var findings: [StringFinding] = []
        var seen = Set<String>()
        var buf = [UInt8]()

        let bytes = [UInt8](data)  // 一次性拷贝以便扫描

        func flush() {
            guard buf.count >= 4 else { buf.removeAll(); return }
            var s = String(decoding: buf, as: UTF8.self)
            // 仅保留含可打印字符的串
            s = s.trimmingCharacters(in: .whitespacesAndNewlines)
            guard s.count >= 3, !seen.contains(s) else { buf.removeAll(); return }
            seen.insert(s)
            let kind = classify(s)
            if kind != "plain" || s.count >= 6 {
                if findings.count < maxTotal {
                    findings.append(StringFinding(text: s, kind: kind))
                }
            }
            buf.removeAll()
        }

        for b in bytes {
            // 可打印 ASCII 或连续 UTF-8 高字节
            if b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127) || b >= 128 {
                buf.append(b)
                if buf.count >= 1024 { flush() }  // 防止超长串
            } else {
                flush()
            }
        }
        flush()
        return findings
    }

    // MARK: - 分类

    static func classify(_ s: String) -> String {
        if let url = extractURL(s), !url.isEmpty { return urlKind(url) }
        if isIP(s) { return "ip" }
        if isDomain(s) { return "domain" }
        if looksLikeEmail(s) { return "email" }
        if looksLikePhone(s) { return "phone" }
        if looksLikeKey(s) { return "key" }
        if s.hasPrefix("/") || s.hasPrefix("var/") || s.hasPrefix("tmp/") { return "path" }
        if s.hasPrefix("http") || s.hasPrefix("www.") { return "url" }
        return "plain"
    }

    static func extractURL(_ s: String) -> String? {
        let lower = s.lowercased()
        for prefix in ["https://", "http://", "wss://", "ws://", "ftp://"] {
            if lower.hasPrefix(prefix) {
                return String(s.dropFirst(prefix.count))
            }
        }
        if lower.hasPrefix("www.") { return s }
        return nil
    }

    static func urlKind(_ s: String) -> String {
        let lower = s.lowercased()
        if lower.hasPrefix("https://") { return "https" }
        if lower.hasPrefix("wss://") { return "wss" }
        if lower.hasPrefix("ws://") { return "ws" }
        if lower.hasPrefix("ftp://") { return "ftp" }
        return "http"
    }

    static func isIP(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        for p in parts {
            guard let v = Int(p), v >= 0, v <= 255 else { return false }
        }
        return true
    }

    static func isDomain(_ s: String) -> Bool {
        let lower = s.lowercased()
        guard lower.contains("."), !lower.contains(" "), !lower.contains("/") else { return false }
        guard lower.hasSuffix(".com") || lower.hasSuffix(".net") || lower.hasSuffix(".org") ||
              lower.hasSuffix(".cn") || lower.hasSuffix(".io") || lower.hasSuffix(".cc") ||
              lower.hasSuffix(".top") || lower.hasSuffix(".xyz") || lower.hasSuffix(".club") ||
              lower.hasSuffix(".info") || lower.hasSuffix(".biz") || lower.hasSuffix(".app") ||
              lower.hasSuffix(".shop") || lower.hasSuffix(".ru") || lower.hasSuffix(".me") else {
            return false
        }
        let host = lower.split(separator: ":").first.map(String.init) ?? lower
        return host.count > 3 && host.count < 64
    }

    static func looksLikeEmail(_ s: String) -> Bool {
        guard s.contains("@"), s.contains("."), !s.contains(" ") else { return false }
        let parts = s.split(separator: "@")
        guard parts.count == 2 else { return false }
        return parts[1].contains(".") && parts[0].count > 0
    }

    static func looksLikePhone(_ s: String) -> Bool {
        let digits = s.filter { $0.isNumber }
        guard digits.count >= 7, digits.count <= 20 else { return false }
        let nonDigit = s.filter { !$0.isNumber && !"+-() ".contains($0) }
        return nonDigit.isEmpty
    }

    static func looksLikeKey(_ s: String) -> Bool {
        let lower = s.lowercased()
        let keywords = ["api", "key", "secret", "token", "password", "passwd", "auth",
                        "jwt", "private", "bearer", "appid", "apikey", "credential", "salt"]
        for kw in keywords {
            if lower.contains(kw), lower.count >= 8 { return true }
        }
        // 高熵串（疑似密钥）
        if s.count >= 32 {
            let alnum = s.filter { $0.isLetter || $0.isNumber }
            if alnum.count == s.count {
                return true
            }
        }
        return false
    }

    /// 判断是否为内网/保留地址
    static func isPrivateIP(_ s: String) -> Bool {
        guard isIP(s) else { return false }
        let parts = s.split(separator: ".").map { Int($0) ?? 0 }
        if parts[0] == 10 { return true }
        if parts[0] == 172 && (parts[1] >= 16 && parts[1] <= 31) { return true }
        if parts[0] == 192 && parts[1] == 168 { return true }
        if parts[0] == 127 { return true }
        if parts[0] == 0 || parts[0] == 169 { return true }
        return false
    }

    // MARK: - 凭据 / 密码提取

    /// 从字符串发现中筛出疑似凭据（密码/API Key/Token/密钥/JWT 等）
    static func extractCredentials(from findings: [StringFinding], source: String) -> [CredentialFinding] {
        var creds = [CredentialFinding]()
        var seen = Set<String>()
        for f in findings {
            let t = f.text
            if seen.contains(t) { continue }
            let lower = t.lowercased()
            var type: String? = nil
            var sev: Severity = .medium

            if lower.contains("-----begin") || lower.contains("private key") || lower.contains("rsa private") ||
               lower.hasPrefix("-----") || t.contains("MII") || lower.contains("sha256withrsa") {
                type = "privateKey"; sev = .critical
            } else if lower.contains("password=") || lower.contains("passwd=") || lower.contains("pwd=") ||
                      lower.contains("password:") || lower == "password" {
                type = "password"; sev = .high
            } else if lower.contains("api_key") || lower.contains("apikey") || lower.contains("api-key") ||
                      lower.contains("appid") || lower.contains("app_id") {
                type = "apiKey"; sev = .high
            } else if lower.contains("access_token") || lower.contains("token=") || lower.contains("refresh_token") {
                type = "token"; sev = .high
            } else if lower.contains("client_secret") || lower.contains("secret=") || lower.contains("consumer_secret") {
                type = "secret"; sev = .critical
            } else if lower.contains("bearer ") || (lower.contains("jwt") && t.count > 40) {
                type = "bearer"; sev = .high
            } else if looksLikeJWT(t) {
                type = "jwt"; sev = .critical
            } else if f.kind == "key" && t.count >= 24 {
                type = "secret"; sev = .medium
            } else if looksLikeBase64(t) && t.count >= 20 {
                type = "base64"; sev = .medium
            }

            if let ty = type {
                seen.insert(t)
                creds.append(CredentialFinding(text: t, type: ty, source: source, severity: sev))
            }
        }
        return creds.sorted { $0.severity.rawValue > $1.severity.rawValue }
    }

    private static func looksLikeJWT(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count == 3 else { return false }
        return s.count > 60 && s.count < 4000
    }

    private static func looksLikeBase64(_ s: String) -> Bool {
        guard s.count >= 16 else { return false }
        let allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        return s.filter { allowed.contains($0) }.count == s.count
    }

    /// 字符串逐项危险等级
    static func severity(kind: String, text: String) -> Severity {
        let lower = text.lowercased()
        switch kind {
        case "http": return .high
        case "ip":
            return isPrivateIP(text) ? .critical : .high
        case "domain": return .medium
        case "email": return .medium
        case "phone": return .medium
        case "key": return looksLikeJWT(text) ? .critical : (text.count >= 24 ? .high : .medium)
        case "path": return .low
        case "url": return .medium
        default:
            if lower.contains("password") || lower.contains("secret") || lower.contains("token") || lower.contains("api_key") { return .high }
            if lower.contains("upload") || lower.contains("/api/") || lower.contains("webhook") || lower.contains("callback") { return .medium }
            if lower.contains("http://") { return .high }
            return .low
        }
    }
}
