import Foundation

/// Info.plist / embedded.mobileprovision 解析
enum AnalyzerPlist {

    static func parse(_ data: Data) -> PlistInfo? {
        guard let obj = propertyList(data) as? [String: Any] else { return nil }
        var info = PlistInfo.empty

        info.bundleID = str(obj["CFBundleIdentifier"])
        info.displayName = str(obj["CFBundleDisplayName"])
        info.name = str(obj["CFBundleName"])
        info.shortVersion = str(obj["CFBundleShortVersionString"])
        info.buildVersion = str(obj["CFBundleVersion"])
        info.minOS = str(obj["MinimumOSVersion"])

        if let fam = obj["UIDeviceFamily"] as? [Any] {
            info.deviceFamily = fam.compactMap { ($0 as? Int).map { $0 == 1 ? "iPhone" : ($0 == 2 ? "iPad" : "\($0)") } }
        }
        if let plat = obj["CFBundleSupportedPlatforms"] as? [Any] {
            info.supportedPlatforms = plat.compactMap { $0 as? String }
        }
        if let urlTypes = obj["CFBundleURLTypes"] as? [[String: Any]] {
            var schemes = [String]()
            for t in urlTypes {
                if let s = t["CFBundleURLSchemes"] as? [Any] {
                    for x in s {
                        if let str = x as? String, !schemes.contains(str) { schemes.append(str) }
                    }
                }
            }
            info.urlSchemes = schemes
        }
        if let bm = obj["UIBackgroundModes"] as? [Any] {
            info.backgroundModes = bm.compactMap { $0 as? String }
        }
        if let ats = obj["NSAppTransportSecurity"] as? [String: Any] {
            info.atsAllowsArbitraryLoads = bool(ats["NSAllowsArbitraryLoads"])
            if let ex = ats["NSExceptionDomains"] as? [String: Any] {
                info.atsExceptions = ex.keys.sorted()
            }
        }
        if let loc = obj["CFBundleLocalizations"] as? [Any] {
            info.localizations = loc.compactMap { $0 as? String }
        } else if let dev = str(obj["CFBundleDevelopmentRegion"]) as String?, !dev.isEmpty {
            info.localizations = [dev]
        }

        // 权限
        info.permissions = extractPermissions(obj)

        // 扁平化原始键
        var raw: [String: String] = [:]
        for (k, v) in obj {
            if let s = v as? String { raw[k] = s }
            else if let b = v as? Bool { raw[k] = b ? "true" : "false" }
            else if let i = v as? Int { raw[k] = "\(i)" }
            else if let a = v as? [Any] { raw[k] = a.map { "\($0)" }.joined(separator: ", ") }
            else if let d = v as? [String: Any] { raw[k] = "<dict \(d.count)>" }
        }
        info.rawKeys = raw
        return info
    }

    // MARK: - 权限提取

    private static let highRiskPermissions: [String: (String, String)] = [
        "NSCameraUsageDescription": ("相机", "可调用设备摄像头拍照/录像，恶意应用可用于偷拍、录制勒索视频"),
        "NSPhotoLibraryUsageDescription": ("相册", "可读取设备相册中的图片与视频，恶意应用可窃取并上传个人私密照片"),
        "NSPhotoLibraryAddUsageDescription": ("保存相册", "可向相册写入图片/视频，用于保存被诱导录制的勒索内容"),
        "NSMicrophoneUsageDescription": ("麦克风", "可录制音频，恶意应用可窃听或录制勒索视频"),
        "NSLocationWhenInUseUsageDescription": ("定位(前台)", "可获取实时位置，用于跟踪用户行踪"),
        "NSLocationAlwaysUsageDescription": ("定位(常驻)", "可后台持续获取位置，跟踪行踪"),
        "NSLocationAlwaysAndWhenInUseUsageDescription": ("定位(始终)", "后台持续获取位置，跟踪行踪"),
        "NSContactsUsageDescription": ("通讯录", "可读取通讯录，勒索木马常窃取联系人并威胁群发"),
        "NSCalendarsUsageDescription": ("日历", "可读取日历日程，泄露行程"),
        "NSRemindersUsageDescription": ("提醒事项", "可读取提醒事项，泄露隐私"),
        "NSMotionUsageDescription": ("运动与健身", "可读取运动数据"),
        "NSBluetoothAlwaysUsageDescription": ("蓝牙(始终)", "可后台扫描/连接蓝牙设备"),
        "NSSpeechRecognitionUsageDescription": ("语音识别", "可上传语音进行识别，泄露谈话内容"),
        "NSFaceIDUsageDescription": ("面容ID", "可调用生物识别，需警惕滥用"),
        "NSUserTrackingUsageDescription": ("用户追踪", "可跨App追踪用户行为用于广告"),
        "NSHealthShareUsageDescription": ("健康数据", "可读取健康与健身数据"),
        "NSHealthUpdateUsageDescription": ("健康写入", "可写入健康数据"),
    ]

    private static func extractPermissions(_ obj: [String: Any]) -> [PermissionInfo] {
        var perms = [PermissionInfo]()
        for (key, value) in obj {
            guard let hr = highRiskPermissions[key] else { continue }
            let desc = (value as? String) ?? ""
            perms.append(PermissionInfo(key: key, title: hr.0,
                                        detail: desc.isEmpty ? hr.1 : desc,
                                        highRisk: true))
        }
        // 加入少量非高危但值得记录的配置
        let extra: [(String, String, String)] = [
            ("NSAppleMusicUsageDescription", "媒体资料库", "可读取媒体库资料"),
            ("NSSiriUsageDescription", "Siri", "与 Siri 集成"),
            ("NSHomeKitUsageDescription", "HomeKit", "可访问智能家居数据"),
            ("NFCReaderUsageDescription", "NFC", "可读取 NFC 标签"),
        ]
        for (key, title, desc) in extra {
            if obj[key] != nil {
                perms.append(PermissionInfo(key: key, title: title,
                                            detail: (obj[key] as? String) ?? desc, highRisk: false))
            }
        }
        return perms.sorted { $0.key < $1.key }
    }

    // MARK: - 通用

    private static func propertyList(_ data: Data) -> Any? {
        // 尝试 binary plist 与 XML
        var fmt = PropertyListSerialization.PropertyListFormat.xml
        let o1 = try? PropertyListSerialization.propertyList(from: data, options: [], format: &fmt)
        if o1 != nil { return o1 }
        // 若前面带签名数据头（mobileprovision 常为 DER 后跟 plist），尝试剥离
        if data.count > 100 {
            let body = data.dropFirst(max(0, data.count - 1_500_000))
            let o2 = try? PropertyListSerialization.propertyList(from: Data(body), options: [], format: &fmt)
            if o2 != nil { return o2 }
        }
        return nil
    }

    static func str(_ v: Any?) -> String {
        v as? String ?? ""
    }

    static func bool(_ v: Any?) -> Bool {
        v as? Bool ?? false
    }
}
