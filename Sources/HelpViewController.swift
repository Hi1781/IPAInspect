import UIKit

/// App 内「使用引导 + 免责声明」页
final class HelpViewController: UIViewController, UITableViewDataSource {
    private let seg = UISegmentedControl(items: ["使用引导", "免责声明"])
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private var mode = 0

    private struct Section { let title: String; let rows: [(String, String)] }
    private var data: [Section] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "帮助"
        view.backgroundColor = .systemGroupedBackground

        seg.selectedSegmentIndex = 0
        seg.addTarget(self, action: #selector(changed), for: .valueChanged)
        seg.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(seg)

        tableView.dataSource = self
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 60
        tableView.backgroundColor = .clear
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)

        NSLayoutConstraint.activate([
            seg.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            seg.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            seg.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            tableView.topAnchor.constraint(equalTo: seg.bottomAnchor, constant: 4),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        rebuild()
    }

    @objc private func changed() {
        mode = seg.selectedSegmentIndex
        rebuild()
        tableView.reloadData()
    }

    private func rebuild() {
        data = mode == 0 ? usageSections() : disclaimerSections()
    }

    func numberOfSections(in tableView: UITableView) -> Int { data.count }
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { data[section].rows.count }
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? { data[section].title }
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "help")
            ?? UITableViewCell(style: .subtitle, reuseIdentifier: "help")
        let r = data[indexPath.section].rows[indexPath.row]
        cell.textLabel?.text = r.0
        cell.textLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        cell.textLabel?.numberOfLines = 0
        cell.detailTextLabel?.text = r.1
        cell.detailTextLabel?.numberOfLines = 0
        cell.detailTextLabel?.font = .systemFont(ofSize: 12)
        cell.textLabel?.textColor = r.1.isEmpty ? .secondaryLabel : .label
        return cell
    }

    // MARK: - 内容

    private func usageSections() -> [Section] {
        [
            Section(title: "安装（侧载）", rows: [
                ("IPA 为未签名裸包", "需在设备端侧载签名后运行。推荐 AltStore / SideStore / Sideloadly / LiveContainer。"),
                ("重新签名周期", "免费 Apple ID 签名的包通常每 7 天需重新签名一次。"),
            ]),
            Section(title: "导入并分析", rows: [
                ("① 打开 App", "进入首页（本地样本库）。"),
                ("② 导入 IPA", "点右上角「导入 IPA」，从系统「文件」App 选择 .ipa 文件。"),
                ("③ 等待解析", "大型包需几秒到几十秒，顶部有进度提示。"),
                ("④ 查看结果", "完成后自动进入结果页，本次结果自动保存到样本库。"),
            ]),
            Section(title: "阅读分析结果（9 个页签）", rows: [
                ("概览", "图标、哈希(MD5/SHA1/SHA256/SHA512)、Bundle ID、版本、风险标签、权限饼图、评分。"),
                ("权限", "申请的隐私权限清单，高危权限红色标注 + 风险说明。"),
                ("Plist", "Info.plist 全量字段，可搜索。"),
                ("Mach-O", "架构、段节、加载命令、加密状态、符号表、签名槽、依赖库。"),
                ("字符串", "二进制内硬编码字符串分类，URL/IP/域名/邮箱/密钥，可搜索。"),
                ("依赖", "系统 / 三方 / 内嵌库分类，识别逆向相关库。"),
                ("风险", "0~100 评分 + 命中规则详情。"),
                ("结构", "IPA 包文件目录树。"),
                ("签名", "embedded.mobileprovision：开发者证书、Team ID、有效期、Entitlements。"),
            ]),
            Section(title: "导出与样本库", rows: [
                ("导出报告", "结果页右上角分享：Markdown + JSON 审计报告。"),
                ("样本库", "首页列表保存历史分析结果，可再次打开或左滑删除。"),
            ]),
            Section(title: "已知限制", rows: [
                ("FairPlay 加密包", "App Store 下载的 IPA 只可解析 Plist 与包结构，Mach-O 内部字符串/符号不可读（系统级保护）。"),
                ("静态分析", "不含动态 hook / 沙盒运行能力；class-dump、YARA 等需外部工具。"),
            ]),
        ]
    }

    private func disclaimerSections() -> [Section] {
        [
            Section(title: "合法用途边界", rows: [
                ("✅ 允许", "对自己开发的 App、本人持有样本、或明确授权的第三方样本做安全审计与隐私风险评估。"),
                ("❌ 禁止", "逆向破解 / 去除 DRM、分析或传播恶意软件、破解他人付费应用、窃取商业机密、未经授权的商业审计。"),
            ]),
            Section(title: "技术限制", rows: [
                ("仅静态分析", "不包含动态执行、代码注入或脱壳能力。"),
                ("FairPlay 限制", "加密包只能解析 Plist 与包结构，内部字符串与符号不可读取——这是系统级保护，非工具缺陷。"),
            ]),
            Section(title: "风险与责任", rows: [
                ("结果仅供参考", "风险评分、权限标记、URL 提取等不构成恶意软件鉴定或法律结论。"),
                ("责任承担", "对目标样本的分析请确保你有合法权利；因使用本工具或其产物产生的直接或间接后果由使用者自行承担。"),
            ]),
            Section(title: "版本", rows: [
                ("IPAInspect v1.1.0", "本地离线 IPA 静态分析器（iOS 侧载版）。本项目仅用于合法的应用安全研究与学习。"),
            ]),
        ]
    }
}
