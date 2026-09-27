import Foundation
import ZInflate

/// 极简 ZIP 读取器：解析 EOCD + 中央目录，支持 stored / deflate 两种压缩，用于读取 IPA 内容。
/// 不依赖系统解压 API，仅用自带的 zlib 包装函数解 raw deflate。
struct ZipEntry {
    var name: String
    var method: Int
    var compSize: Int
    var uncompSize: Int
    var crc: UInt32
    var localOffset: Int
    var isDirectory: Bool
}

enum ZipReadError: Error {
    case notZip
    case badEOCD
    case entryNotFound
    case inflateFailed
}

final class ZipReader {
    private let data: Data
    var entries: [ZipEntry] = []

    init(data: Data) throws {
        self.data = data
        try parseCentralDirectory()
    }

    /// 按路径（大小写不敏感，忽略末尾 /）查找条目
    func find(_ path: String) -> ZipEntry? {
        let p = path.hasSuffix("/") ? String(path.dropLast()) : path
        return entries.first { $0.name.caseInsensitiveCompare(p) == .orderedSame }
    }

    func read(_ path: String) -> Data? {
        guard let e = find(path) else { return nil }
        return readEntry(e)
    }

    func readEntry(_ e: ZipEntry) -> Data? {
        guard e.isDirectory == false else { return nil }
        guard let local = localHeader(e.localOffset) else { return nil }
        // local header: sig(4)+6x2字节固定 + nameLen(2)+extraLen(2)，共 30 字节
        var dataStart = e.localOffset + 30 + local.nameLen + local.extraLen
        // 数据描述符（data descriptor）在需要时可能紧跟；flags bit3 表示用 descriptor，
        // 但中央目录已给出准确大小，直接按大小截取数据区。
        let available = data.count - dataStart
        if available < e.compSize { return nil }
        let comp = Data(data[dataStart..<(dataStart + e.compSize)])
        if e.method == 0 {   // stored
            return comp
        }
        if e.method == 8 {   // deflate
            return inflateRaw(comp, expected: e.uncompSize)
        }
        return nil
    }

    private func inflateRaw(_ comp: Data, expected: Int) -> Data? {
        var out = [UInt8](repeating: 0, count: expected)
        let outCount = out.count
        let outLen = comp.withUnsafeBytes { cbuf -> Int in
            out.withUnsafeMutableBytes { obuf in
                var len: UInt = 0
                let r = zraw_inflate(cbuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                     UInt(comp.count),
                                     obuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                     UInt(outCount),
                                     &len)
                guard r == 0 else { return -1 }
                return Int(len)
            }
        }
        guard outLen >= 0 else { return nil }
        return Data(out[0..<outLen])
    }

    // MARK: - 中央目录解析

    private func parseCentralDirectory() throws {
        // EOCD: "PK\x05\x06" (0x06054b50)，位于文件末尾 65557 字节内
        guard data.count >= 22 else { throw ZipReadError.notZip }
        let tailStart = max(0, data.count - 65_557)
        var eocdOff = -1
        let sig0 = data[tailStart]
        _ = sig0
        for i in stride(from: data.count - 22, through: tailStart, by: -1) {
            if data[i] == 0x50, data[i + 1] == 0x4b, data[i + 2] == 0x05, data[i + 3] == 0x06 {
                eocdOff = i
                break
            }
        }
        guard eocdOff >= 0 else { throw ZipReadError.notZip }
        guard eocdOff + 22 <= data.count else { throw ZipReadError.badEOCD }
        let total = le16(data, eocdOff + 10)
        let cdSize = le32(data, eocdOff + 12)
        let cdOff = le32(data, eocdOff + 16)
        guard cdOff + cdSize <= data.count else { throw ZipReadError.badEOCD }
        var pos = cdOff
        var count = 0
        while pos + 46 <= data.count && count < total {
            let sig = le32(data, pos)
            guard sig == 0x02014b50 else { break }
            let method = le16(data, pos + 10)
            let compSize = le32(data, pos + 20)
            let uncompSize = le32(data, pos + 24)
            let nameLen = le16(data, pos + 28)
            let extraLen = le16(data, pos + 30)
            let commentLen = le16(data, pos + 32)
            let crc = le32(data, pos + 16)
            let localOff = le32(data, pos + 42)
            let start = pos + 46
            guard start + nameLen <= data.count else { break }
            let nameData = data.subdata(in: start..<(start + nameLen))
            let name = String(decoding: nameData, as: UTF8.self)
            entries.append(ZipEntry(name: name,
                                    method: method,
                                    compSize: compSize,
                                    uncompSize: uncompSize,
                                    crc: UInt32(crc),
                                    localOffset: localOff,
                                    isDirectory: name.hasSuffix("/")))
            count += 1
            pos = start + nameLen + extraLen + commentLen
        }
        guard count > 0 else { throw ZipReadError.badEOCD }
    }

    private struct LocalHeader {
        var nameLen: Int
        var extraLen: Int
    }

    private func localHeader(_ offset: Int) -> LocalHeader? {
        guard offset + 30 <= data.count else { return nil }
        let sig = le32(data, offset)
        guard sig == 0x04034b50 else { return nil }
        return LocalHeader(nameLen: le16(data, offset + 26),
                           extraLen: le16(data, offset + 28))
    }

    // MARK: - 小端读取
    private func le16(_ d: Data, _ o: Int) -> Int {
        guard o + 1 < d.count else { return 0 }
        return Int(d[o]) | (Int(d[o + 1]) << 8)
    }

    private func le32(_ d: Data, _ o: Int) -> Int {
        guard o + 3 < d.count else { return 0 }
        let b0 = UInt32(d[o]), b1 = UInt32(d[o + 1]), b2 = UInt32(d[o + 2]), b3 = UInt32(d[o + 3])
        return Int(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }
}
