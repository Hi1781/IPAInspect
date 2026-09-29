import UIKit

// MARK: - 概览

final class OverviewDetailVC: UIViewController {
    private let result: AnalysisResult
    private let scroll = UIScrollView()
    private let stack = UIStackView()

    init(result: AnalysisResult) {
        self.result = result
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -12),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -24)
        ])
        build()
    }

    private func card(_ v: UIView) -> UIView {
        let c = UIView()
        c.backgroundColor = .secondarySystemGroupedBackground
        c.layer.cornerRadius = 12
        c.translatesAutoresizingMaskIntoConstraints = false
        v.translatesAutoresizingMaskIntoConstraints = false
        c.addSubview(v)
        NSLayoutConstraint.activate([
            v.topAnchor.constraint(equalTo: c.topAnchor, constant: 12),
            v.leadingAnchor.constraint(equalTo: c.leadingAnchor, constant: 12),
            v.trailingAnchor.constraint(equalTo: c.trailingAnchor, constant: -12),
            v.bottomAnchor.constraint(equalTo: c.bottomAnchor, constant: -12)
        ])
        return c
    }

    private func kvRow(_ k: String, _ v: String) -> UIView {
        let row = UIView()
        let kL = UITheme.makeLabel(k, size: 13, weight: .semibold)
        kL.textColor = .secondaryLabel
        let vL = UITheme.makeLabel(v, size: 14)
        vL.textAlignment = .right
        vL.numberOfLines = 0
        kL.translatesAutoresizingMaskIntoConstraints = false
        vL.translatesAutoresizingMaskIntoConstraints = false
        row.addSubview(kL); row.addSubview(vL)
        NSLayoutConstraint.activate([
            kL.leadingAnchor.constraint(equalTo: row.leadingAnchor),
            kL.topAnchor.constraint(equalTo: row.topAnchor),
            kL.widthAnchor.constraint(equalToConstant: 120),
            vL.leadingAnchor.constraint(equalTo: kL.trailingAnchor, constant: 8),
            vL.trailingAnchor.constraint(equalTo: row.trailingAnchor),
            vL.topAnchor.constraint(equalTo: row.topAnchor),
            vL.bottomAnchor.constraint(equalTo: row.bottomAnchor, constant: -4),
            row.heightAnchor.constraint(greaterThanOrEqualToConstant: 24)
        ])
        return row
    }

    private func build() {
        // 头部卡片
        let header = UIView()
        let iconView = UIImageView()
        iconView.layer.cornerRadius = 14
        iconView.clipsToBounds = true
        iconView.contentMode = .scaleAspectFit
        iconView.backgroundColor = .systemGray5
        if let b64 = result.iconDataBase64, let data = Data(base64Encoded: b64), let img = UIImage(data: data) {
            iconView.image = img
        }
        iconView.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(iconView)

        let name = UITheme.makeLabel(result.plist.displayName.isEmpty ? result.plist.name : result.plist.displayName,
                                     size: 18, weight: .bold)
        let sub = UITheme.makeLabel("\(result.fileName) · \(UITheme.formatBytes(result.fileSize))", size: 13)
        sub.textColor = .secondaryLabel
        let bundle = UITheme.makeLabel("Bundle ID: \(result.plist.bundleID.isEmpty ? "-" : result.plist.bundleID)", size: 13)
        bundle.textColor = .secondaryLabel
        let badge = UITheme.riskBadge(result.riskLevel)
        badge.translatesAutoresizingMaskIntoConstraints = false

        let infoStack = UIStackView(arrangedSubviews: [name, sub, bundle])
        infoStack.axis = .vertical
        infoStack.spacing = 4
        infoStack.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(infoStack)
        header.addSubview(badge)

        NSLayoutConstraint.activate([
            iconView.leadingAnchor.constraint(equalTo: header.leadingAnchor),
            iconView.topAnchor.constraint(equalTo: header.topAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 64),
            iconView.heightAnchor.constraint(equalToConstant: 64),
            infoStack.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            infoStack.trailingAnchor.constraint(equalTo: header.trailingAnchor),
            infoStack.topAnchor.constraint(equalTo: header.topAnchor, constant: 2),
            badge.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            badge.topAnchor.constraint(equalTo: infoStack.bottomAnchor, constant: 6),
            badge.bottomAnchor.constraint(equalTo: header.bottomAnchor)
        ])
        stack.addArrangedSubview(card(header))

        // 综合文字描述报告
        let repV = UIView()
        let repTitle = UITheme.makeLabel("综合文字描述报告", size: 14, weight: .semibold)
        repTitle.translatesAutoresizingMaskIntoConstraints = false
        repV.addSubview(repTitle)
        let repBody = UITheme.makeLabel(ReportGenerator.summary(result), size: 13)
        repBody.numberOfLines = 0
        repBody.translatesAutoresizingMaskIntoConstraints = false
        repV.addSubview(repBody)
        let repCopy = UIButton(type: .system)
        repCopy.setTitle("复制报告", for: .normal)
        repCopy.titleLabel?.font = .systemFont(ofSize: 13, weight: .medium)
        repCopy.addTarget(self, action: #selector(copyReport), for: .touchUpInside)
        repCopy.translatesAutoresizingMaskIntoConstraints = false
        repV.addSubview(repCopy)
        NSLayoutConstraint.activate([
            repTitle.topAnchor.constraint(equalTo: repV.topAnchor),
            repTitle.leadingAnchor.constraint(equalTo: repV.leadingAnchor),
            repBody.topAnchor.constraint(equalTo: repTitle.bottomAnchor, constant: 8),
            repBody.leadingAnchor.constraint(equalTo: repV.leadingAnchor),
            repBody.trailingAnchor.constraint(equalTo: repV.trailingAnchor),
            repCopy.topAnchor.constraint(equalTo: repBody.bottomAnchor, constant: 10),
            repCopy.trailingAnchor.constraint(equalTo: repV.trailingAnchor),
            repCopy.bottomAnchor.constraint(equalTo: repV.bottomAnchor)
        ])
        stack.addArrangedSubview(card(repV))

        // 哈希卡片
        let hashV = UIView()
        let hashTitle = UITheme.makeLabel("文件哈希", size: 14, weight: .semibold)
        hashTitle.translatesAutoresizingMaskIntoConstraints = false
        hashV.addSubview(hashTitle)
        let md5 = UITheme.makeLabel("MD5    \(result.md5)", size: 12)
        let sha1 = UITheme.makeLabel("SHA1   \(result.sha1)", size: 12)
        let sha256 = UITheme.makeLabel("SHA256 \(result.sha256)", size: 12)
        let sha512 = UITheme.makeLabel("SHA512 \(result.sha512)", size: 12)
        let hs = UIStackView(arrangedSubviews: [md5, sha1, sha256, sha512])
        hs.axis = .vertical; hs.spacing = 4
        hs.translatesAutoresizingMaskIntoConstraints = false
        hashV.addSubview(hs)
        NSLayoutConstraint.activate([
            hashTitle.topAnchor.constraint(equalTo: hashV.topAnchor),
            hashTitle.leadingAnchor.constraint(equalTo: hashV.leadingAnchor),
            hs.topAnchor.constraint(equalTo: hashTitle.bottomAnchor, constant: 8),
            hs.leadingAnchor.constraint(equalTo: hashV.leadingAnchor),
            hs.trailingAnchor.constraint(equalTo: hashV.trailingAnchor),
            hs.bottomAnchor.constraint(equalTo: hashV.bottomAnchor)
        ])
        stack.addArrangedSubview(card(hashV))

        // 关键信息
        let info = UIView()
        let it = UITheme.makeLabel("关键信息", size: 14, weight: .semibold)
        it.translatesAutoresizingMaskIntoConstraints = false
        info.addSubview(it)
        var rows: [UIView] = [it]
        rows.append(kvRow("版本", "\(result.plist.shortVersion.isEmpty ? "-" : result.plist.shortVersion) (build \(result.plist.buildVersion.isEmpty ? "-" : result.plist.buildVersion))"))
        rows.append(kvRow("最低系统", result.plist.minOS.isEmpty ? "-" : "iOS \(result.plist.minOS)"))
        rows.append(kvRow("设备", result.plist.deviceFamily.isEmpty ? "-" : result.plist.deviceFamily.joined(separator: "/")))
        rows.append(kvRow("架构", result.machO.architectures.joined(separator: ", ")))
        rows.append(kvRow("平台", result.machO.platform.isEmpty ? "-" : result.machO.platform))
        rows.append(kvRow("加密", result.machO.encrypted ? "FairPlay 加密" : "未加密"))
        rows.append(kvRow("权限数", "\(result.plist.permissions.count)（高危 \(result.plist.permissions.filter { $0.highRisk }.count)）"))
        rows.append(kvRow("提取 URL", "\(result.urls.count)"))
        rows.append(kvRow("依赖库", "\(result.deps.count)"))
        rows.append(kvRow("签名证书", result.signing?.hasProfile == true ? "已包含 (embedded.mobileprovision)" : "未包含"))
        rows.append(kvRow("分析时间", result.analyzedAt))
        let rs = UIStackView(arrangedSubviews: rows.map { v in v })
        rs.axis = .vertical; rs.spacing = 6
        rs.translatesAutoresizingMaskIntoConstraints = false
        info.addSubview(rs)
        NSLayoutConstraint.activate([
            rs.topAnchor.constraint(equalTo: info.topAnchor),
            rs.leadingAnchor.constraint(equalTo: info.leadingAnchor),
            rs.trailingAnchor.constraint(equalTo: info.trailingAnchor),
            rs.bottomAnchor.constraint(equalTo: info.bottomAnchor)
        ])
        stack.addArrangedSubview(card(info))

        // 图表
        let pie = PieChartView(title: "权限分布")
        let dist = AnalyzerRisk.permissionDistribution(result.plist)
        pie.slices = [.init(value: Double(dist.high), color: .systemRed, label: "高危权限"),
                      .init(value: Double(dist.normal), color: .systemBlue, label: "普通/配置")]
        if dist.high == 0 && dist.normal == 0 {
            pie.slices = [.init(value: 1, color: .systemGray3, label: "未声明权限")]
        }
        pie.heightAnchor.constraint(equalToConstant: 300).isActive = true
        stack.addArrangedSubview(card(pie))
        // 权限分布说明（修复：无权限时的可读提示）
        let pieNote = UITheme.makeLabel(
            dist.high + dist.normal == 0
                ? "该应用未声明任何 iOS 隐私权限"
                : "高危 \(dist.high) 项 · 普通/配置 \(dist.normal) 项",
            size: 13)
        pieNote.textColor = .secondaryLabel
        pieNote.textAlignment = .center
        pieNote.translatesAutoresizingMaskIntoConstraints = false
        let pieNoteWrap = card(pieNote)
        pieNoteWrap.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(pieNoteWrap)

        let scoreBar = ScoreBarView()
        scoreBar.score = result.score
        scoreBar.heightAnchor.constraint(equalToConstant: 70).isActive = true
        stack.addArrangedSubview(card(scoreBar))

        let barItems: [(String, Int, UIColor)] = [
            ("恶意级别", result.findings.filter { $0.level == .malicious }.count, .systemRed),
            ("可疑级别", result.findings.filter { $0.level == .suspicious }.count, .systemOrange),
            ("低风险", result.findings.filter { $0.level == .low }.count, .systemYellow)
        ]
        let bars = BarRowView(items: barItems)
        bars.heightAnchor.constraint(equalToConstant: 120).isActive = true
        stack.addArrangedSubview(card(bars))

        if let note = result.encryptionNote {
            let n = UITheme.makeLabel("⚠️ \(note)", size: 13)
            n.textColor = .systemOrange
            stack.addArrangedSubview(card(n))
        }
    }

    @objc private func copyReport() {
        UIPasteboard.general.string = ReportGenerator.summary(result)
        let a = UIAlertController(title: "已复制", message: "综合文字描述报告已复制到剪贴板", preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "好", style: .default))
        present(a, animated: true)
    }
}

// MARK: - 权限

final class PermissionDetailVC: UITableViewController {
    private let result: AnalysisResult
    private var items: [PermissionInfo] = []

    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
        items = result.plist.permissions
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 60
    }

    override func numberOfSections(in tableView: UITableView) -> Int { 1 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        items.isEmpty ? 1 : items.count
    }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        "隐私权限声明（共 \(items.count) 项）"
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if items.isEmpty {
            let c = UITableViewCell(style: .default, reuseIdentifier: "empty")
            c.textLabel?.text = "未声明隐私权限"
            c.textLabel?.textColor = .secondaryLabel
            return c
        }
        let p = items[indexPath.row]
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "perm")
        cell.textLabel?.text = p.key
        cell.textLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        cell.textLabel?.numberOfLines = 0
        cell.detailTextLabel?.text = "\(p.title)：\(p.detail)"
        cell.detailTextLabel?.numberOfLines = 0
        cell.detailTextLabel?.font = .systemFont(ofSize: 12)
        let badge = UITheme.makeLabel(p.highRisk ? "高危" : "普通", size: 11, weight: .bold)
        badge.textColor = .white
        badge.backgroundColor = p.highRisk ? .systemRed : .systemBlue
        badge.textAlignment = .center
        badge.layer.cornerRadius = 5
        badge.clipsToBounds = true
        badge.translatesAutoresizingMaskIntoConstraints = false
        cell.contentView.addSubview(badge)
        NSLayoutConstraint.activate([
            badge.trailingAnchor.constraint(equalTo: cell.contentView.trailingAnchor, constant: -14),
            badge.topAnchor.constraint(equalTo: cell.contentView.topAnchor, constant: 10),
            badge.widthAnchor.constraint(equalToConstant: 42),
            badge.heightAnchor.constraint(equalToConstant: 20)
        ])
        return cell
    }
}

// MARK: - Plist

final class PlistDetailVC: UITableViewController {
    private let result: AnalysisResult
    private var rows: [(String, String)] = []
    private let search = UISearchController(searchResultsController: nil)

    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
        buildRows()
    }
    required init?(coder: NSCoder) { fatalError() }

    private func buildRows() {
        var r = [(String, String)]()
        let p = result.plist
        r.append(("CFBundleIdentifier", p.bundleID))
        r.append(("CFBundleDisplayName", p.displayName))
        r.append(("CFBundleName", p.name))
        r.append(("CFBundleShortVersionString", p.shortVersion))
        r.append(("CFBundleVersion", p.buildVersion))
        r.append(("MinimumOSVersion", p.minOS))
        r.append(("UIDeviceFamily", p.deviceFamily.joined(separator: ", ")))
        r.append(("CFBundleSupportedPlatforms", p.supportedPlatforms.joined(separator: ", ")))
        r.append(("URL Schemes", p.urlSchemes.joined(separator: ", ")))
        r.append(("UIBackgroundModes", p.backgroundModes.joined(separator: ", ")))
        r.append(("ATS 允许任意加载", p.atsAllowsArbitraryLoads ? "是" : "否"))
        r.append(("ATS 例外域名", p.atsExceptions.isEmpty ? "-" : p.atsExceptions.joined(separator: ", ")))
        r.append(("本地化", p.localizations.joined(separator: ", ")))
        for (k, v) in p.rawKeys.sorted(by: { $0.key < $1.key }) {
            if !["CFBundleIdentifier", "CFBundleDisplayName", "CFBundleName", "CFBundleShortVersionString",
                  "CFBundleVersion", "MinimumOSVersion"].contains(k) {
                r.append((k, v))
            }
        }
        rows = r
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
        search.obscuresBackgroundDuringPresentation = false
        search.searchResultsUpdater = self
        navigationItem.searchController = search
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 50
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { rows.count }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .value1, reuseIdentifier: "plist")
        let row = rows[indexPath.row]
        cell.textLabel?.text = row.0
        cell.textLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
        cell.textLabel?.numberOfLines = 0
        cell.detailTextLabel?.text = row.1
        cell.detailTextLabel?.numberOfLines = 0
        cell.detailTextLabel?.font = .systemFont(ofSize: 12)
        return cell
    }
}

extension PlistDetailVC: UISearchResultsUpdating {
    func updateSearchResults(for searchController: UISearchController) {
        guard let q = searchController.searchBar.text?.lowercased(), !q.isEmpty else { return }
        rows = rows.filter { $0.0.lowercased().contains(q) || $0.1.lowercased().contains(q) }
        tableView.reloadData()
    }
}

// MARK: - Mach-O

final class MachODetailVC: UITableViewController {
    private let result: AnalysisResult
    private var rows: [(String, String, Bool)] = []

    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
        build()
    }
    required init?(coder: NSCoder) { fatalError() }

    private func build() {
        let m = result.machO
        rows.append(("架构", m.architectures.joined(separator: ", "), false))
        rows.append(("文件类型", m.filetype, false))
        rows.append(("平台", m.platform, false))
        rows.append(("最低系统", m.minOS, false))
        rows.append(("SDK 版本", m.sdkVersion, false))
        rows.append(("UUID", m.uuid.isEmpty ? "-" : m.uuid, false))
        rows.append(("FairPlay 加密", m.encrypted ? "是 (cryptid=\(m.cryptID))" : "否", m.encrypted))
        rows.append(("代码签名槽", m.hasCodeSignature ? "存在" : "缺失", !m.hasCodeSignature))
        rows.append(("PIE/ASLR", m.pie ? "启用" : "未启用", !m.pie))
        rows.append(("段数量", "\(m.segments.count)", false))
        for seg in m.segments {
            rows.append(("  段 \(seg.name)", "vmsize \(seg.vmsize) · filesize \(seg.filesize) · \(seg.protections)", false))
        }
        rows.append(("加载命令", m.loadCommands.joined(separator: ", "), false))
        rows.append(("链接动态库", "\(m.linkedDylibs.count)", false))
        for lib in m.linkedDylibs {
            rows.append(("  \(lib)", "", false))
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 50
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { rows.count }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "macho")
        let r = rows[indexPath.row]
        cell.textLabel?.text = r.0
        cell.textLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
        cell.textLabel?.numberOfLines = 0
        cell.detailTextLabel?.text = r.1
        cell.detailTextLabel?.numberOfLines = 0
        cell.detailTextLabel?.font = .systemFont(ofSize: 12)
        if r.2 { cell.textLabel?.textColor = .systemOrange }
        return cell
    }
}

// MARK: - 字符串 / URL

final class StringsDetailVC: UIViewController, UITableViewDataSource, UITableViewDelegate, UISearchResultsUpdating {
    private struct SRow { let text: String; let tag: String; let sev: Severity; let source: String }

    private let result: AnalysisResult
    private let seg = UISegmentedControl(items: ["URL / IP / 域名", "全部字符串", "凭据 / 密码"])
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private let emptyLabel = UILabel()
    private let search = UISearchController(searchResultsController: nil)
    private var mode = 0
    private var filtered: [SRow] = []

    init(result: AnalysisResult) {
        self.result = result
        super.init(nibName: nil, bundle: nil)
        refreshData()
    }
    required init?(coder: NSCoder) { fatalError() }

    private func refreshData() {
        switch mode {
        case 0:
            filtered = result.urls.map { u in
                let tag = urlTag(u)
                let sev: Severity = (u.kind == "http" || (u.kind == "ip" && u.suspicious)) ? .high
                                    : (u.kind == "ip" ? .medium : (u.kind == "domain" ? .medium : .low))
                return SRow(text: u.url, tag: tag, sev: sev, source: "主程序")
            }
        case 1:
            filtered = result.strings.map {
                SRow(text: $0.text, tag: "[\($0.kind)]", sev: AnalyzerStrings.severity(kind: $0.kind, text: $0.text), source: "主程序")
            }
        default:
            filtered = (result.credentials ?? []).map {
                SRow(text: $0.text, tag: "\($0.type)", sev: $0.severity, source: $0.source)
            }
        }
    }

    private func urlTag(_ u: URLFinding) -> String {
        if u.kind == "ip" { return u.suspicious ? "内网IP" : "公网IP" }
        if u.kind == "domain" { return "域名" }
        if u.kind == "http" { return "明文HTTP" }
        if u.kind == "https" { return "HTTPS" }
        return u.kind
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        seg.selectedSegmentIndex = 0
        seg.addTarget(self, action: #selector(changed), for: .valueChanged)
        seg.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(seg)
        tableView.dataSource = self
        tableView.delegate = self
        tableView.backgroundColor = .clear
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 40
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)

        emptyLabel.text = "没有可显示的内容"
        emptyLabel.textAlignment = .center
        emptyLabel.numberOfLines = 0
        emptyLabel.textColor = .secondaryLabel
        emptyLabel.font = .systemFont(ofSize: 14)
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(emptyLabel)
        NSLayoutConstraint.activate([
            emptyLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: 40)
        ])

        NSLayoutConstraint.activate([
            seg.topAnchor.constraint(equalTo: view.topAnchor, constant: 4),
            seg.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            seg.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            tableView.topAnchor.constraint(equalTo: seg.bottomAnchor, constant: 8),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        search.obscuresBackgroundDuringPresentation = false
        search.searchResultsUpdater = self
        parent?.navigationItem.searchController = search
        updateEmpty()
    }

    private func updateEmpty() {
        emptyLabel.isHidden = !filtered.isEmpty
    }

    @objc private func changed() {
        mode = seg.selectedSegmentIndex
        refreshData()
        tableView.reloadData()
        updateEmpty()
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { filtered.count }
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "str")
        let f = filtered[indexPath.row]
        cell.textLabel?.text = f.text
        cell.textLabel?.font = .systemFont(ofSize: 13)
        cell.textLabel?.numberOfLines = 0
        cell.textLabel?.textColor = f.sev.rawValue >= 3 ? .systemOrange : .label
        cell.detailTextLabel?.text = "\(f.tag)\(f.source.isEmpty ? "" : " · \(f.source)")"
        cell.detailTextLabel?.font = .systemFont(ofSize: 11)
        cell.detailTextLabel?.textColor = .secondaryLabel
        let tag = UITheme.severityTag(f.sev, width: 40)
        cell.accessoryView = tag
        return cell
    }

    func updateSearchResults(for searchController: UISearchController) {
        guard let q = searchController.searchBar.text?.lowercased(), !q.isEmpty else {
            refreshData(); tableView.reloadData(); updateEmpty(); return
        }
        refreshData()
        filtered = filtered.filter { $0.text.lowercased().contains(q) || $0.tag.lowercased().contains(q) }
        tableView.reloadData()
        updateEmpty()
    }
}

// MARK: - 依赖

final class DepsDetailVC: UITableViewController {
    private let result: AnalysisResult
    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        result.deps.isEmpty ? 1 : result.deps.count
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if result.deps.isEmpty {
            let c = UITableViewCell(style: .default, reuseIdentifier: "e")
            c.textLabel?.text = "未检测到动态库依赖"
            c.textLabel?.textColor = .secondaryLabel
            return c
        }
        let d = result.deps[indexPath.row]
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "dep")
        cell.textLabel?.text = d.name
        cell.textLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        // 依赖逐项危险等级
        var sev: Severity = .safe
        if d.note.contains("危险") || d.note.contains("逆向") { sev = .critical }
        else if d.kind == "embedded" { sev = .medium }
        else if d.kind == "thirdparty" { sev = .medium }
        else if d.note.contains("加密") { sev = .low }
        cell.detailTextLabel?.text = "[\(kindName(d.kind))] \(d.note)"
        cell.detailTextLabel?.font = .systemFont(ofSize: 12)
        cell.accessoryView = UITheme.severityTag(sev, width: 42)
        return cell
    }

    private func kindName(_ k: String) -> String {
        switch k {
        case "system": return "系统"
        case "thirdparty": return "三方"
        default: return "内嵌"
        }
    }
}

// MARK: - 风险

final class RiskDetailVC: UITableViewController {
    private let result: AnalysisResult
    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 140
    }

    override func numberOfSections(in tableView: UITableView) -> Int { result.findings.isEmpty ? 1 : 2 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if result.findings.isEmpty { return 1 }
        return section == 0 ? 1 : result.findings.count
    }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? "风险评分" : "风险发现明细"
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if result.findings.isEmpty {
            let c = UITableViewCell(style: .default, reuseIdentifier: "e")
            c.textLabel?.text = "未发现风险项（或样本为加密包，能力受限）"
            c.textLabel?.textColor = .secondaryLabel
            return c
        }
        if indexPath.section == 0 {
            let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "score")
            cell.textLabel?.text = "风险评分 \(result.score) / 100 · \(result.riskLevel.label)"
            cell.textLabel?.textColor = UITheme.riskColor(result.riskLevel)
            cell.textLabel?.font = .systemFont(ofSize: 18, weight: .bold)
            let lvl: [(Int, String)] = [(0, "安全"), (20, "低风险"), (45, "可疑"), (75, "恶意")]
            let desc = lvl.map { "≥\($0.0)=\($0.1)" }.joined(separator: "  ")
            cell.detailTextLabel?.text = "分级阈值：" + desc
            cell.detailTextLabel?.font = .systemFont(ofSize: 12)
            cell.detailTextLabel?.numberOfLines = 0
            cell.detailTextLabel?.lineBreakMode = .byWordWrapping
            return cell
        }
        let f = result.findings[indexPath.row]
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "risk")
        cell.textLabel?.text = "\(f.level.label) · \(f.title)（+\(f.points)分）"
        cell.textLabel?.textColor = UITheme.riskColor(f.level)
        cell.textLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        cell.textLabel?.numberOfLines = 0
        cell.textLabel?.lineBreakMode = .byWordWrapping
        let d = "证据：\(f.source)\n\(f.detail)\n建议：\(f.suggestion)"
        cell.detailTextLabel?.text = d
        cell.detailTextLabel?.numberOfLines = 0
        cell.detailTextLabel?.font = .systemFont(ofSize: 12)
        cell.detailTextLabel?.lineBreakMode = .byWordWrapping
        cell.accessoryView = UITheme.severityTag(riskLevelSeverity(f.level), width: 42)
        return cell
    }

    private func riskLevelSeverity(_ l: RiskLevel) -> Severity {
        switch l {
        case .safe: return .safe
        case .low: return .low
        case .suspicious: return .high
        case .malicious: return .critical
        }
    }
}

// MARK: - 签名证书

final class SignDetailVC: UITableViewController {
    private let result: AnalysisResult
    private var rows: [(String, String)] = []
    private var entitlements: [(String, String)] = []

    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
        build()
    }
    required init?(coder: NSCoder) { fatalError() }

    private func build() {
        guard let s = result.signing, s.hasProfile else { return }
        rows.append(("配置文件", "embedded.mobileprovision"))
        rows.append(("AppID 名称", s.appIDName.isEmpty ? "-" : s.appIDName))
        rows.append(("Team ID", s.teamIdentifier.isEmpty ? "-" : s.teamIdentifier))
        rows.append(("App ID 前缀", s.appIDPrefix.isEmpty ? "-" : s.appIDPrefix))
        rows.append(("有效期至", s.expirationDate.isEmpty ? "-" : s.expirationDate))
        rows.append(("TimeToLive", s.timeToLive > 0 ? "\(s.timeToLive) 天" : "-"))
        rows.append(("注册设备数", s.provisionedDevices > 0 ? "\(s.provisionedDevices) 台" : "未限制"))
        entitlements = s.entitlements.sorted { $0.key < $1.key }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 60
        if result.signing?.hasProfile == true, result.provisioningDataBase64 != nil {
            let export = UIBarButtonItem(title: "导出签名文件", style: .plain, target: self, action: #selector(exportSigning))
            navigationItem.rightBarButtonItem = export
        }
    }

    @objc private func exportSigning() {
        guard let b64 = result.provisioningDataBase64, let data = Data(base64Encoded: b64) else {
            let a = UIAlertController(title: "无可导出签名文件", message: "样本未包含 embedded.mobileprovision", preferredStyle: .alert)
            a.addAction(UIAlertAction(title: "好", style: .default))
            present(a, animated: true)
            return
        }
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(result.fileName)-embedded.mobileprovision")
        try? data.write(to: tmp)
        let ac = UIActivityViewController(activityItems: [tmp], applicationActivities: nil)
        ac.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItem
        present(ac, animated: true)
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        (result.signing?.hasProfile ?? false) ? 2 : 1
    }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        guard result.signing?.hasProfile == true else { return 1 }
        return section == 0 ? rows.count : entitlements.count
    }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        guard result.signing?.hasProfile == true else { return nil }
        return section == 0 ? "签名信息" : "Entitlements（\(entitlements.count)）"
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard result.signing?.hasProfile == true else {
            let c = UITableViewCell(style: .default, reuseIdentifier: "e")
            c.textLabel?.text = "包内未包含 embedded.mobileprovision（可能为开发/企业导出或未签名包）"
            c.textLabel?.numberOfLines = 0
            c.textLabel?.textColor = .secondaryLabel
            return c
        }
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "sign")
        if indexPath.section == 0 {
            let r = rows[indexPath.row]
            cell.textLabel?.text = r.0
            cell.textLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
            cell.detailTextLabel?.text = r.1
            cell.detailTextLabel?.numberOfLines = 0
            cell.detailTextLabel?.font = .systemFont(ofSize: 12)
            cell.accessoryView = UITheme.severityTag(signRowSeverity(r.0), width: 42)
        } else {
            let e = entitlements[indexPath.row]
            cell.textLabel?.text = e.0
            cell.textLabel?.font = .systemFont(ofSize: 12, weight: .semibold)
            cell.textLabel?.textColor = .systemOrange
            cell.detailTextLabel?.text = e.1
            cell.detailTextLabel?.numberOfLines = 0
            cell.detailTextLabel?.font = .systemFont(ofSize: 12)
            cell.accessoryView = UITheme.severityTag(entitlementSeverity(e.0, e.1), width: 42)
        }
        return cell
    }

    private func signRowSeverity(_ key: String) -> Severity {
        if key.contains("有效期") { return .medium }
        if key.contains("Team ID") || key.contains("App ID") { return .low }
        return .safe
    }

    private func entitlementSeverity(_ key: String, _ value: String) -> Severity {
        let lower = key.lowercased()
        if lower.contains("get-task-allow") { return value.lowercased() == "true" ? .high : .safe }
        if lower.contains("aps-environment") || lower.contains("push") { return .medium }
        if lower.contains("homekit") || lower.contains("healthkit") || lower.contains("wallet") { return .medium }
        if lower.contains("external-accessory") || lower.contains("location") || lower.contains("camera") { return .high }
        if lower.contains("application-identifier") || lower.contains("team-identifier") { return .safe }
        return .low
    }
}

// MARK: - 结构

final class StructureDetailVC: UITableViewController {
    private let result: AnalysisResult
    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { result.tree.count }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        "IPA 文件结构（\(result.fileCount) 文件 / \(result.directoryCount) 目录）"
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: "tree")
        let e = result.tree[indexPath.row]
        cell.textLabel?.text = e.isDirectory ? "📁 \(e.path)" : "📄 \(e.path)"
        cell.textLabel?.font = .systemFont(ofSize: 12)
        cell.textLabel?.numberOfLines = 0
        if !e.isDirectory {
            cell.detailTextLabel?.text = UITheme.formatBytes(e.size)
            cell.detailTextLabel?.font = .systemFont(ofSize: 11)
        } else {
            cell.detailTextLabel?.text = nil
        }
        cell.accessoryView = UITheme.severityTag(fileSeverity(e), width: 42)
        return cell
    }

    /// 结构条目逐项危险等级（依据文件名/后缀/内容审查）
    private func fileSeverity(_ e: ZipEntryInfo) -> Severity {
        let lower = e.path.lowercased()
        if lower.hasSuffix("embedded.mobileprovision") { return .medium }
        if lower.contains("password") || lower.contains("secret") || lower.contains("apikey") ||
           lower.contains("credential") || lower.contains(".key") { return .critical }
        if lower.hasSuffix(".plist") || lower.hasSuffix(".json") || lower.hasSuffix(".js") ||
           lower.hasSuffix(".html") || lower.hasSuffix(".conf") { return .medium }
        if lower.contains(".app/") && !e.isDirectory { return .low }
        if lower.contains("frameworks/") || lower.contains("plugins/") { return .medium }
        if let audit = result.resourceAudit, audit.contains(where: { $0.path.contains(e.path) }) { return .high }
        return .low
    }
}

// MARK: - 动态分析建议（基于静态证据生成的可执行分析计划）

final class DynamicAnalysisDetailVC: UITableViewController {
    private let result: AnalysisResult
    private var enabled = true
    private var sections: [(String, [String])] = []

    init(result: AnalysisResult) {
        self.result = result
        super.init(style: .insetGrouped)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        tableView.backgroundColor = .clear
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 70
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            title: "导出脚本包", style: .plain, target: self, action: #selector(exportBundle))
        rebuild()
    }

    @objc private func exportBundle() {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ipa-dyn-\(UUID().uuidString.prefix(8))")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let urls = DynamicScriptGen.exportBundle(result, into: dir)
        let ac = UIActivityViewController(activityItems: urls, applicationActivities: nil)
        ac.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItem
        present(ac, animated: true)
    }

    private func rebuild() {
        sections.removeAll()
        guard enabled else { return }

        // 建议 Frida Hook 点（依据静态证据）
        var hooks = [String]()
        for p in result.plist.permissions {
            switch p.key {
            case "NSCameraUsageDescription": hooks.append("ObjC: AVCaptureSession#startRunning → 记录拍照/录像")
            case "NSMicrophoneUsageDescription": hooks.append("ObjC: AVAudioRecorder#record → 记录录音")
            case "NSPhotoLibraryUsageDescription": hooks.append("ObjC: PHPhotoLibrary#requestAuthorization → 记录相册访问")
            case "NSContactsUsageDescription": hooks.append("ObjC: CNContactStore#fetchUnifiedContacts → 记录通讯录读取")
            case "NSLocationAlwaysUsageDescription", "NSLocationWhenInUseUsageDescription":
                hooks.append("ObjC: CLLocationManager#requestLocation / startUpdatingLocation → 记录定位")
            case "NSLocalNetworkUsageDescription": hooks.append("ObjC: NWBrowser / Bonjour → 记录局域网扫描")
            default: break
            }
        }
        if result.plist.atsAllowsArbitraryLoads || !result.urls.filter({ $0.kind != "https" }).isEmpty {
            hooks.append("ObjC: NSURLSession#dataTaskWithRequest / NSURLConnection → 抓取明文HTTP请求")
        }
        if !(result.credentials ?? []).isEmpty {
            hooks.append("ObjC: 网络层回调打印请求体 → 验证凭据是否随包外传")
        }
        if result.machO.encrypted == false {
            hooks.append("ObjC: NSFileManager#writeToFile → 追踪落盘文件")
        }
        if !hooks.isEmpty {
            sections.append(("建议 Frida Hook 点（需越狱 + frida-server）", hooks))
        }

        // 建议 UI 自动化流程（Appium / 手动）
        var ui = [String]()
        ui.append("冷启动 → 观察首次请求是否直连内网/明文地址")
        ui.append("授予全部权限 → 触发各隐私功能，观察是否有非预期上传")
        ui.append("触发登录/注册 → 抓包验证账号密码是否明文传输")
        ui.append("后台切回 → 观察是否仍在上传（后台常驻证据）")
        ui.append("断网启动 → 观察本地逻辑降级，识别硬编码地址")
        sections.append(("建议 UI 自动化流程（Appium 或手动）", ui))

        // 预期采集数据
        var expect = [String]()
        expect.append("网络请求详情：URL、方法、请求体、是否含凭据/私密数据")
        expect.append("函数调用链：涉及相机/麦克风/通讯录/定位的调用序列")
        expect.append("运行时参数：授权回调结果、上传文件路径与内容")
        expect.append("落盘文件：沙盒内被写入的数据文件")
        sections.append(("预期采集数据（与静态结果关联）", expect))

        // 关联静态证据
        var related = [String]()
        if !(result.credentials ?? []).isEmpty {
            related.append("静态发现 \(result.credentials!.count) 条凭据，动态需验证其是否被用于上传")
        }
        let ext = result.urls.filter { $0.kind != "https" }
        if !ext.isEmpty {
            related.append("静态发现 \(ext.count) 条非HTTPS外链，动态需抓取验证")
        }
        let criticalFiles = (result.resourceAudit ?? []).filter { $0.severity == .critical }
        if !criticalFiles.isEmpty {
            related.append("静态发现 \(criticalFiles.count) 个含高危机密的文件，动态需确认是否被读取/上传")
        }
        if !related.isEmpty {
            sections.append(("与静态分析的关联", related))
        }

        // 可导出的脚本文件
        sections.append(("可导出的脚本包（右上角导出，拿来即跑）", [
            "hook.js — Frida ObjC Hook（网络/相机/麦克风/通讯录/定位/局域网/落盘）",
            "test_dynamic.py — Appium UI 自动化骨架（启动/授权/触发/后台）",
            "mitm_filter.py — mitmproxy 过滤器（标记外联 + 检测凭据外传）",
            "run_dynamic.sh — 一键编排（mitmproxy + frida + pytest）",
            "README.txt — 步骤与免责声明"
        ]))

        // 模拟动态执行轨迹（沙盒内演示）
        let sim = DynamicSimulator.simulate(result)
        if !sim.isEmpty {
            sections.append(("模拟动态执行轨迹（沙盒内演示）", sim.map { "\($0.time) [\($0.tag)] \($0.detail)" }))
            let simScore = DynamicSimulator.simulatedScore(result)
            sections.append(("模拟动态判定（含运行行为加成）", [
                "模拟评分 \(simScore.points)/100 · \(simScore.verdict)",
                "说明：静态分 \(result.score) + 模拟高风险行为加成；真实判定以 frida/mitmproxy 采集为准"
            ]))
        }
    }

    override func numberOfSections(in tableView: UITableView) -> Int { enabled ? sections.count + 1 : 1 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if section == 0 { return 1 }
        return sections[section - 1].1.count
    }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? "开启动态分析建议" : sections[section - 1].0
    }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        section == 0 ? "本 App 为静态分析器；真实动态分析需在越狱设备或电脑端（Frida / Appium）执行，此处仅生成可执行的分析计划。" : nil
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if indexPath.section == 0 {
            let cell = UITableViewCell(style: .default, reuseIdentifier: "toggle")
            cell.textLabel?.text = "生成动态分析计划"
            cell.textLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
            let sw = UISwitch()
            sw.isOn = enabled
            sw.addTarget(self, action: #selector(toggled(_:)), for: .valueChanged)
            cell.accessoryView = sw
            return cell
        }
        let cell = tableView.dequeueReusableCell(withIdentifier: "dyn")
            ?? UITableViewCell(style: .subtitle, reuseIdentifier: "dyn")
        let text = sections[indexPath.section - 1].1[indexPath.row]
        cell.textLabel?.text = "· \(text)"
        cell.textLabel?.font = .systemFont(ofSize: 13)
        cell.textLabel?.numberOfLines = 0
        cell.detailTextLabel?.text = nil
        return cell
    }

    @objc private func toggled(_ sw: UISwitch) {
        enabled = sw.isOn
        rebuild()
        tableView.reloadData()
    }
}
