import Foundation
import CommonCrypto

/// 基于 CommonCrypto 的哈希计算
enum AnalyzerHash {
    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func md5(_ data: Data) -> String {
        var buf = [UInt8](repeating: 0, count: 16)
        data.withUnsafeBytes { p in
            _ = CC_MD5(p.baseAddress, CC_LONG(data.count), &buf)
        }
        return hex(buf)
    }

    static func sha1(_ data: Data) -> String {
        var buf = [UInt8](repeating: 0, count: 20)
        data.withUnsafeBytes { p in
            _ = CC_SHA1(p.baseAddress, CC_LONG(data.count), &buf)
        }
        return hex(buf)
    }

    static func sha256(_ data: Data) -> String {
        var buf = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { p in
            _ = CC_SHA256(p.baseAddress, CC_LONG(data.count), &buf)
        }
        return hex(buf)
    }

    static func sha512(_ data: Data) -> String {
        var buf = [UInt8](repeating: 0, count: 64)
        data.withUnsafeBytes { p in
            _ = CC_SHA512(p.baseAddress, CC_LONG(data.count), &buf)
        }
        return hex(buf)
    }
}
