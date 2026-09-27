import Foundation

/// arm64 / armv7 Mach-O 二进制解析器（只读，纯结构解析）
enum AnalyzerMachO {

    private static let LC_REQ_DYLIB = 0x80000000
    private static let LC_SEGMENT_64 = 0x19
    private static let LC_SYMTAB = 0x2
    private static let LC_LOAD_DYLIB = 0xC
    private static let LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
    private static let LC_UUID = 0x1B
    private static let LC_ENCRYPTION_INFO = 0x21
    private static let LC_CODE_SIGNATURE = 0x1D
    private static let LC_BUILD_VERSION = 0x32
    private static let LC_ENCRYPTION_INFO_64 = 0x2C

    static func parse(_ data: Data) -> MachOInfo? {
        guard data.count >= 32 else { return nil }
        var info = MachOInfo.empty
        let d = data

        // 魔数
        let magic = le32(d, 0)
        var offset = 0
        var is64 = false
        switch magic {
        case 0xfeedfacf: is64 = true; offset = 0        // MH_MAGIC_64
        case 0xcffaedfe: is64 = true; offset = 4        // 大端 MH_CIGAM_64
        case 0xfeedface: is64 = false; offset = 0
        case 0xcefaedfe: is64 = false; offset = 4
        default: return nil
        }
        let cpuField = Int(le32(d, offset + 4))
        let subtypeField = Int(le32(d, offset + 8))
        let filetype = Int(le32(d, offset + 12))
        let ncmds = Int(le32(d, offset + 16))
        let flags = Int(le32(d, offset + 24))

        // 架构
        switch cpuField {
        case 0x0100000c: info.architectures.append(subtypeField == 0x00000080 ? "arm64e" : "arm64")
        case 0x00000007:
            info.architectures.append((subtypeField & 0xff) == 0x00000009 ? "armv7" : "armv7")
        case 0x01000007: info.architectures.append("x86_64")
        default: info.architectures.append("0x" + String(cpuField, radix: 16))
        }
        info.filetype = fileTypeName(filetype)
        info.pie = (flags & 0x200000) != 0   // MH_PIE

        let headerSize = is64 ? 32 : 28
        var pos = headerSize
        for _ in 0..<ncmds {
            guard pos + 8 <= d.count else { break }
            let cmd = Int(le32(d, pos))
            let cmdsize = Int(le32(d, pos + 4))
            guard cmdsize >= 8 && pos + cmdsize <= d.count else { break }
            info.loadCommands.append(loadCommandName(cmd))

            switch cmd {
            case LC_SEGMENT_64:
                // segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4)
                if pos + 72 <= d.count {
                    let name = cstring(d, pos + 8, 16)
                    let vmaddr = le64(d, pos + 24)
                    let vmsize = le64(d, pos + 32)
                    let fileoff = le64(d, pos + 40)
                    let filesize = le64(d, pos + 48)
                    let maxprot = le32(d, pos + 56)
                    let initprot = le32(d, pos + 60)
                    let protStr = "init=\(protString(Int(initprot))) max=\(protString(Int(maxprot)))"
                    info.segments.append(MachOSegment(name: name, vmsize: vmsize,
                                                      filesize: filesize, fileoff: fileoff,
                                                      protections: protStr))
                    _ = vmaddr
                }
            case LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB:
                // cmd(4)+cmdsize(4) 后是 dylib 结构：name_off(4) timestamp(4) current_version(4) compat_version(4)
                // name_off 相对 dylib 结构起点（= cmd + 8）
                if pos + 16 <= d.count {
                    let nameOff = Int(le32(d, pos + 8))
                    let strStart = pos + 8 + nameOff
                    let name = cstring(d, strStart, 256)
                    if !name.isEmpty {
                        if name.hasPrefix("@rpath/") || name.hasPrefix("@executable_path/") || name.hasPrefix("@loader_path/") {
                            let base = name.split(separator: "/").last.map(String.init) ?? name
                            info.linkedDylibs.append(base)
                        } else {
                            info.linkedDylibs.append(name)
                        }
                    }
                }
            case LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64:
                // cryptoff(4) cryptsize(4) cryptid(4)
                if pos + 20 <= d.count {
                    let cryptid = Int(le32(d, pos + 16))
                    info.cryptID = cryptid
                    info.encrypted = cryptid > 0
                }
            case LC_UUID:
                if pos + 24 <= d.count {
                    let bytes = d[(pos + 8)..<(pos + 24)]
                    info.uuid = bytes.map { String(format: "%02x", $0) }.joined()
                }
            case LC_CODE_SIGNATURE:
                if pos + 16 <= d.count {
                    info.hasCodeSignature = le32(d, pos + 12) > 0
                }
            case LC_BUILD_VERSION:
                // platform(4) minos(4) sdk(4) ntools(4)
                if pos + 20 <= d.count {
                    let platform = Int(le32(d, pos + 8))
                    info.platform = platformName(platform)
                    let minos = le32(d, pos + 12)
                    let sdk = le32(d, pos + 16)
                    info.minOS = versionString(minos)
                    info.sdkVersion = versionString(sdk)
                }
            case LC_SYMTAB:
                if pos + 24 <= d.count {
                    let symoff = Int(le32(d, pos + 8))
                    let nsyms = Int(le32(d, pos + 12))
                    let stroff = Int(le32(d, pos + 16))
                    let strsize = Int(le32(d, pos + 20))
                    // 解析符号表（尽力而为）：提取导出符号与导入的显式符号
                    parseSymbolTable(d, symoff: symoff, nsyms: nsyms,
                                     stroff: stroff, strsize: strsize,
                                     is64: is64, info: &info)
                }
            default:
                break
            }
            pos += cmdsize
        }
        // 框架归类
        for lib in info.linkedDylibs {
            let base = lib.split(separator: "/").last.map(String.init) ?? lib
            let frameworkName = base.replacingOccurrences(of: ".framework", with: "")
            if !info.linkedFrameworks.contains(frameworkName) {
                info.linkedFrameworks.append(frameworkName)
            }
        }
        return info
    }

    // MARK: - 符号表解析

    private static func parseSymbolTable(_ d: Data, symoff: Int, nsyms: Int,
                                         stroff: Int, strsize: Int,
                                         is64: Bool, info: inout MachOInfo) {
        let entrySize = is64 ? 16 : 12
        let strBase = stroff
        for i in 0..<min(nsyms, 200_000) {
            let base = symoff + i * entrySize
            guard base + (is64 ? 16 : 12) <= d.count else { break }
            let strx = Int(le32(d, base))
            let type = Int(le8(d, base + 4))
            let strIndex = strBase + strx
            let nType = type & 0x0e   // N_TYPE
            let isExt = (type & 0x01) != 0   // N_EXT
            let name = cstring(d, strIndex, 120)
            if name.isEmpty { continue }
            if nType == 0x01 {   // N_SECT
                if isExt && !info.exportedSymbols.contains(name) {
                    info.exportedSymbols.append(name)
                }
            } else if nType == 0x02 {   // N_ABS
                if isExt && !info.exportedSymbols.contains(name) {
                    info.exportedSymbols.append(name)
                }
            }
            _ = strsize
        }
        // 截断避免 UI 卡顿
        if info.exportedSymbols.count > 3000 { info.exportedSymbols = Array(info.exportedSymbols.prefix(3000)) }
    }

    // MARK: - 工具函数

    private static func cstring(_ d: Data, _ off: Int, _ maxLen: Int) -> String {
        guard off >= 0 && off < d.count else { return "" }
        var end = off
        let limit = min(d.count, off + maxLen)
        while end < limit, d[end] != 0 { end += 1 }
        guard end > off else { return "" }
        return String(decoding: d[off..<end], as: UTF8.self)
    }

    private static func le16(_ d: Data, _ o: Int) -> Int {
        guard o + 1 < d.count else { return 0 }
        return Int(d[o]) | (Int(d[o + 1]) << 8)
    }

    private static func le32(_ d: Data, _ o: Int) -> Int {
        guard o + 3 < d.count else { return 0 }
        let b0 = UInt32(d[o]), b1 = UInt32(d[o + 1]), b2 = UInt32(d[o + 2]), b3 = UInt32(d[o + 3])
        return Int(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }

    private static func le8(_ d: Data, _ o: Int) -> Int {
        guard o < d.count else { return 0 }
        return Int(d[o])
    }

    private static func le64(_ d: Data, _ o: Int) -> UInt64 {
        guard o + 7 < d.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(d[o + i]) << (UInt64(i) * 8) }
        return v
    }

    private static func versionString(_ v: Int) -> String {
        let major = (v >> 16) & 0xff
        let minor = (v >> 8) & 0xff
        let patch = v & 0xff
        return "\(major).\(minor).\(patch)"
    }

    private static func protString(_ p: Int) -> String {
        var s = ""
        if p & 1 != 0 { s += "r" }
        if p & 2 != 0 { s += "w" }
        if p & 4 != 0 { s += "x" }
        return s.isEmpty ? "-" : s
    }

    private static func fileTypeName(_ t: Int) -> String {
        switch t {
        case 0x2: return "MH_EXECUTE (可执行)"
        case 0x6: return "MH_DYLIB (动态库)"
        case 0x8: return "MH_BUNDLE (Bundle)"
        case 0x3: return "MH_FVMLIB"
        default: return "0x" + String(t, radix: 16)
        }
    }

    private static func platformName(_ p: Int) -> String {
        switch p {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 5: return "bridgeOS"
        case 6: return "mac Catalyst"
        case 7: return "iOS Simulator"
        case 8: return "tvOS Simulator"
        case 9: return "watchOS Simulator"
        case 11: return "visionOS"
        default: return "platform(\(p))"
        }
    }

    private static func loadCommandName(_ cmd: Int) -> String {
        switch cmd {
        case 0x1: return "LC_SEGMENT"
        case LC_SEGMENT_64: return "LC_SEGMENT_64"
        case 0x2: return "LC_SYMTAB"
        case 0xB: return "LC_LOAD_DYLIB"
        case 0xC: return "LC_LOAD_DYLIB"
        case 0x10: return "LC_ID_DYLIB"
        case 0x1B: return "LC_UUID"
        case 0x1D: return "LC_CODE_SIGNATURE"
        case 0x21: return "LC_ENCRYPTION_INFO"
        case 0x2C: return "LC_ENCRYPTION_INFO_64"
        case 0x32: return "LC_BUILD_VERSION"
        case 0x14: return "LC_UNIXTHREAD"
        case 0x80000000 | 0x18: return "LC_LOAD_WEAK_DYLIB"
        default: return "LC(0x" + String(cmd, radix: 16) + ")"
        }
    }
}
