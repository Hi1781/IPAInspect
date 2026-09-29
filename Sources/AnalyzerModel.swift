import Foundation

// MARK: - 风险等级
enum RiskLevel: Int, Codable {
    case safe = 0
    case low = 1
    case suspicious = 2
    case malicious = 3

    var label: String {
        switch self {
        case .safe: return "安全"
        case .low: return "低风险"
        case .suspicious: return "可疑"
        case .malicious: return "恶意软件"
        }
    }

    var colorIndex: Int {
        switch self {
        case .safe: return 0      // 绿
        case .low: return 1       // 黄
        case .suspicious: return 2 // 橙
        case .malicious: return 3  // 红
        }
    }

    static func fromScore(_ score: Int) -> RiskLevel {
        if score >= 75 { return .malicious }
        if score >= 45 { return .suspicious }
        if score >= 20 { return .low }
        return .safe
    }
}

// MARK: - 逐项危险等级（用于字符串/依赖/结构/签名等每条内容的标签）
enum Severity: Int, Codable {
    case safe = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    var label: String {
        switch self {
        case .safe: return "安全"
        case .low: return "低"
        case .medium: return "中"
        case .high: return "高"
        case .critical: return "危险"
        }
    }

    var colorIndex: Int {
        switch self {
        case .safe: return 0      // 绿
        case .low: return 1       // 青
        case .medium: return 2    // 黄
        case .high: return 3      // 橙
        case .critical: return 4  // 红
        }
    }
}

// MARK: - 凭据 / 密码发现
struct CredentialFinding: Codable {
    var text: String
    var type: String          // password / apiKey / token / secret / privateKey / jwt / bearer / base64
    var source: String        // 来源（主程序 / 资源文件路径）
    var severity: Severity
}

// MARK: - 资源内容审查（扫描多个文件后的逐文件结论）
struct ResourceFinding: Codable {
    var path: String
    var severity: Severity
    var findings: [String]    // 该文件命中的敏感项描述
}

// MARK: - 单项风险发现
struct RiskFinding: Codable {
    var title: String
    var detail: String
    var source: String        // 证据来源（权限名/字符串/配置键）
    var points: Int           // 风险分（0~100 累加）
    var level: RiskLevel
    var suggestion: String
}

// MARK: - 权限项
struct PermissionInfo: Codable {
    var key: String           // 如 NSCameraUsageDescription
    var title: String         // 中文名称
    var detail: String        // 中文说明
    var highRisk: Bool        // 是否高危
}

// MARK: - URL / 链接发现
struct URLFinding: Codable {
    var url: String
    var kind: String          // http / https / ws / wss / ip / domain / other
    var suspicious: Bool
}

// MARK: - 字符串发现
struct StringFinding: Codable {
    var text: String
    var kind: String          // url / ip / domain / email / phone / key / path / plain
}

// MARK: - Mach-O 段
struct MachOSegment: Codable {
    var name: String
    var vmsize: UInt64
    var filesize: UInt64
    var fileoff: UInt64
    var protections: String
}

// MARK: - Mach-O 信息
struct MachOInfo: Codable {
    var architectures: [String]   // arm64 / armv7 / x86_64
    var filetype: String
    var platform: String
    var minOS: String
    var sdkVersion: String
    var uuid: String
    var encrypted: Bool           // FairPlay 加密
    var cryptID: Int
    var hasCodeSignature: Bool
    var segments: [MachOSegment]
    var loadCommands: [String]
    var linkedFrameworks: [String]
    var linkedDylibs: [String]
    var importedFunctions: [String]  // 从符号表提取的显式导入（尽力而为）
    var exportedSymbols: [String]
    var pie: Bool
}

// MARK: - Plist 信息
struct PlistInfo: Codable {
    var bundleID: String
    var displayName: String
    var name: String
    var shortVersion: String
    var buildVersion: String
    var minOS: String
    var deviceFamily: [String]
    var supportedPlatforms: [String]
    var urlSchemes: [String]
    var permissions: [PermissionInfo]
    var backgroundModes: [String]
    var atsAllowsArbitraryLoads: Bool
    var atsExceptions: [String]
    var localizations: [String]
    var rawKeys: [String: String]   // 扁平化展示用（字符串值）
}

// MARK: - 包内文件
struct ZipEntryInfo: Codable {
    var path: String
    var size: Int
    var isDirectory: Bool
}

// MARK: - 依赖库
struct DependencyInfo: Codable {
    var name: String
    var kind: String        // system / thirdparty / embedded
    var note: String
}

// MARK: - 签名证书（embedded.mobileprovision）
struct ProvisioningInfo: Codable {
    var hasProfile: Bool
    var appIDName: String
    var teamIdentifier: String
    var appIDPrefix: String
    var expirationDate: String
    var timeToLive: Int
    var provisionedDevices: Int
    var entitlements: [String: String]   // 扁平化键值

    static var empty: ProvisioningInfo {
        ProvisioningInfo(hasProfile: false, appIDName: "", teamIdentifier: "",
                         appIDPrefix: "", expirationDate: "", timeToLive: 0,
                         provisionedDevices: 0, entitlements: [:])
    }
}

// MARK: - 完整分析结果
struct AnalysisResult: Codable {
    var fileName: String
    var fileSize: Int
    var analyzedAt: String
    // 哈希
    var md5: String
    var sha1: String
    var sha256: String
    var sha512: String
    // 结构
    var fileCount: Int
    var directoryCount: Int
    var mainAppPath: String
    var iconDataBase64: String?    // 主图标（预览用）
    // 模块
    var plist: PlistInfo
    var machO: MachOInfo
    var signing: ProvisioningInfo?     // embedded.mobileprovision（可选，旧存档可兼容解码）
    var provisioningDataBase64: String? // 原始 mobileprovision，用于分离导出
    var strings: [StringFinding]
    var credentials: [CredentialFinding]?  // 提取的凭据/密码
    var resourceAudit: [ResourceFinding]?  // 多文件内容审查
    var urls: [URLFinding]
    var deps: [DependencyInfo]
    var tree: [ZipEntryInfo]
    // 风险
    var findings: [RiskFinding]
    var score: Int
    var riskLevel: RiskLevel
    var encryptionNote: String?

    init() {
        fileName = ""
        fileSize = 0
        analyzedAt = ""
        md5 = ""; sha1 = ""; sha256 = ""; sha512 = ""
        fileCount = 0; directoryCount = 0
        mainAppPath = ""
        iconDataBase64 = nil
        plist = PlistInfo.empty
        machO = MachOInfo.empty
        signing = nil
        provisioningDataBase64 = nil
        strings = []; credentials = nil; resourceAudit = nil
        urls = []; deps = []; tree = []
        findings = []; score = 0; riskLevel = .safe
        encryptionNote = nil
    }

    // JSON 导出
    func jsonData() -> Data? {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? enc.encode(self)
    }
}

extension PlistInfo {
    static var empty: PlistInfo {
        PlistInfo(bundleID: "", displayName: "", name: "", shortVersion: "",
                  buildVersion: "", minOS: "", deviceFamily: [], supportedPlatforms: [],
                  urlSchemes: [], permissions: [], backgroundModes: [],
                  atsAllowsArbitraryLoads: false, atsExceptions: [], localizations: [],
                  rawKeys: [:])
    }
}

extension MachOInfo {
    static var empty: MachOInfo {
        MachOInfo(architectures: [], filetype: "", platform: "", minOS: "", sdkVersion: "",
                  uuid: "", encrypted: false, cryptID: 0, hasCodeSignature: false,
                  segments: [], loadCommands: [], linkedFrameworks: [], linkedDylibs: [],
                  importedFunctions: [], exportedSymbols: [], pie: false)
    }
}
