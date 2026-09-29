import UIKit
import UniformTypeIdentifiers

/// 首页：样本列表 + 导入
final class HomeViewController: UIViewController, UITableViewDataSource, UITableViewDelegate,
                                UIDocumentPickerDelegate {
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private let emptyLabel = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "IPA 分析器"
        view.backgroundColor = .systemGroupedBackground
        navigationController?.navigationBar.prefersLargeTitles = true
        let helpBtn = UIBarButtonItem(title: "帮助", style: .plain,
                                      target: self, action: #selector(helpTapped))
        let importMenu = UIMenu(title: "导入", children: [
            UIAction(title: "导入 IPA 安装包", image: UIImage(systemName: "app.badge"), handler: { [weak self] _ in
                self?.importTapped(type: "ipa")
            }),
            UIAction(title: "导入分析报告 (JSON)", image: UIImage(systemName: "doc.text"), handler: { [weak self] _ in
                self?.importTapped(type: "json")
            })
        ])
        let importBtn = UIBarButtonItem(title: "导入", image: UIImage(systemName: "square.and.arrow.down"),
                                        menu: importMenu)
        navigationItem.leftBarButtonItem = helpBtn
        navigationItem.rightBarButtonItem = importBtn

        setupSubviews()
        NotificationCenter.default.addObserver(self, selector: #selector(reload),
                                               name: UIApplication.willEnterForegroundNotification, object: nil)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reload()
    }

    private func setupSubviews() {
        tableView.dataSource = self
        tableView.delegate = self
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 72
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        tableView.register(SampleCell.self, forCellReuseIdentifier: "sample")

        emptyLabel.text = "还没有分析样本\n点击右上角「导入 IPA」开始分析"
        emptyLabel.textAlignment = .center
        emptyLabel.numberOfLines = 0
        emptyLabel.textColor = .secondaryLabel
        emptyLabel.font = .systemFont(ofSize: 16)
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(emptyLabel)
        NSLayoutConstraint.activate([
            emptyLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }

    @objc private func reload() {
        tableView.reloadData()
        let has = !SampleStore.shared.allRecords().isEmpty
        emptyLabel.isHidden = has
    }

    @objc private func helpTapped() {
        navigationController?.pushViewController(HelpViewController(), animated: true)
    }

    @objc private func importTapped(type: String) {
        var types: [UTType] = []
        if type == "json" {
            types = [.json, .data]
        } else {
            types = [UTType(filenameExtension: "ipa") ?? .data, .data]
        }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        present(picker, animated: true)
    }

    // MARK: - DocumentPicker

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first else { return }
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            let a = UIAlertController(title: "读取失败", message: "无法读取所选文件", preferredStyle: .alert)
            a.addAction(UIAlertAction(title: "好", style: .default))
            present(a, animated: true)
            return
        }
        let isJSON = url.pathExtension.lowercased() == "json"
        if isJSON {
            importReport(data: data, fileName: url.lastPathComponent)
        } else {
            analyze(data: data, fileName: url.lastPathComponent)
        }
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {}

    /// 导入已导出的分析报告 JSON（解析并入库，跳过重新分析）
    private func importReport(data: Data, fileName: String) {
        do {
            let result = try JSONDecoder().decode(AnalysisResult.self, from: data)
            var r = result
            if r.analyzedAt.isEmpty {
                let f = DateFormatter()
                f.dateFormat = "yyyy-MM-dd HH:mm:ss"
                r.analyzedAt = f.string(from: Date())
            }
            let id = SampleStore.shared.save(r)
            let rec = SampleStore.shared.record(forID: id)
            let alert = UIAlertController(
                title: "已导入分析报告",
                message: "\(fileName)\n\(rec?.appName ?? "")\n风险评分 \(r.score)/100 · \(r.riskLevel.label)",
                preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "查看", style: .default) { [weak self] _ in
                self?.navigationController?.pushViewController(ResultViewController(resultID: id), animated: true)
            })
            alert.addAction(UIAlertAction(title: "取消", style: .cancel))
            present(alert, animated: true)
        } catch {
            let a = UIAlertController(title: "导入失败", message: "文件不是有效的 IPAInspect 分析报告 JSON：\(error.localizedDescription)", preferredStyle: .alert)
            a.addAction(UIAlertAction(title: "好", style: .default))
            present(a, animated: true)
        }
    }

    // MARK: - 分析

    private func analyze(data: Data, fileName: String) {
        let vc = AnalyzingViewController(fileName: fileName)
        let nav = UINavigationController(rootViewController: vc)
        nav.modalPresentationStyle = .pageSheet
        present(nav, animated: true)

        DispatchQueue.global(qos: .userInitiated).async {
            let engine = IPAEngine()
            engine.progress = { msg, p in
                DispatchQueue.main.async { vc.updateProgress(msg, p) }
            }
            do {
                let result = try engine.analyze(data: data, fileName: fileName)
                let id = SampleStore.shared.save(result)
                DispatchQueue.main.async { [weak self] in
                    nav.dismiss(animated: true) { [weak self] in
                        let detail = ResultViewController(resultID: id)
                        self?.navigationController?.pushViewController(detail, animated: true)
                    }
                }
            } catch {
                let err = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                DispatchQueue.main.async {
                    vc.showError(err)
                }
            }
        }
    }

    // MARK: - TableView

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        SampleStore.shared.allRecords().count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "sample", for: indexPath) as! SampleCell
        let rec = SampleStore.shared.allRecords()[indexPath.row]
        cell.configure(rec)
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let rec = SampleStore.shared.allRecords()[indexPath.row]
        let detail = ResultViewController(resultID: rec.id)
        navigationController?.pushViewController(detail, animated: true)
    }

    func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let rec = SampleStore.shared.allRecords()[indexPath.row]
        let del = UIContextualAction(style: .destructive, title: "删除") { [weak self] _, _, done in
            SampleStore.shared.delete(id: rec.id)
            self?.reload()
            done(true)
        }
        return UISwipeActionsConfiguration(actions: [del])
    }
}

// MARK: - 样本单元格

final class SampleCell: UITableViewCell {
    private let iconView = UIImageView()
    private let nameLabel = UILabel()
    private let metaLabel = UILabel()
    private let badge = UIView()
    private let badgeLabel = UILabel()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        iconView.layer.cornerRadius = 10
        iconView.clipsToBounds = true
        iconView.contentMode = .scaleAspectFit
        iconView.backgroundColor = .secondarySystemBackground
        iconView.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(iconView)

        nameLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(nameLabel)

        metaLabel.font = .systemFont(ofSize: 12)
        metaLabel.textColor = .secondaryLabel
        metaLabel.numberOfLines = 0
        metaLabel.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(metaLabel)

        badge.layer.cornerRadius = 6
        badge.clipsToBounds = true
        badgeLabel.font = .systemFont(ofSize: 11, weight: .bold)
        badgeLabel.textColor = .white
        badgeLabel.translatesAutoresizingMaskIntoConstraints = false
        badge.addSubview(badgeLabel)
        badge.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(badge)

        NSLayoutConstraint.activate([
            iconView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 14),
            iconView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 44),
            iconView.heightAnchor.constraint(equalToConstant: 44),

            badgeLabel.centerXAnchor.constraint(equalTo: badge.centerXAnchor),
            badgeLabel.centerYAnchor.constraint(equalTo: badge.centerYAnchor),

            nameLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 10),
            nameLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            nameLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -14),

            badge.topAnchor.constraint(equalTo: nameLabel.bottomAnchor, constant: 4),
            badge.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            badge.heightAnchor.constraint(greaterThanOrEqualToConstant: 22),

            metaLabel.leadingAnchor.constraint(equalTo: badge.trailingAnchor, constant: 8),
            metaLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -14),
            metaLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -10)
        ])
    }

    required init?(coder: NSCoder) { fatalError() }

    func configure(_ rec: SampleStore.Record) {
        nameLabel.text = rec.appName.isEmpty ? rec.fileName : rec.appName
        let level = RiskLevel(rawValue: rec.riskLevel) ?? .safe
        badge.backgroundColor = UITheme.riskColor(level)
        badgeLabel.text = level.label
        let dateStr = rec.analyzedAt
        let size = UITheme.formatBytes(rec.fileSize)
        metaLabel.text = "\(rec.fileName) · \(size)\nBundle: \(rec.bundleID.isEmpty ? "-" : rec.bundleID)\n\(dateStr) · SHA256 \(rec.sha256.prefix(12))…"
        iconView.image = nil
        if let result = SampleStore.shared.loadResult(id: rec.id), let b64 = result.iconDataBase64,
           let data = Data(base64Encoded: b64), let img = UIImage(data: data) {
            iconView.image = img
        }
    }
}

// MARK: - 分析中页

final class AnalyzingViewController: UIViewController {
    private let fileName: String
    private let spinner = UIActivityIndicatorView(style: .large)
    private let statusLabel = UILabel()
    private let progressView = UIProgressView(progressViewStyle: .default)

    init(fileName: String) {
        self.fileName = fileName
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "分析中"
        let close = UIBarButtonItem(title: "取消", style: .done, target: self, action: #selector(close))
        navigationItem.rightBarButtonItem = close

        spinner.startAnimating()
        spinner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(spinner)

        statusLabel.text = "正在加载 \(fileName)…"
        statusLabel.textAlignment = .center
        statusLabel.font = .systemFont(ofSize: 15)
        statusLabel.numberOfLines = 0
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusLabel)

        progressView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(progressView)

        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            spinner.topAnchor.constraint(equalTo: view.topAnchor, constant: 120),
            statusLabel.topAnchor.constraint(equalTo: spinner.bottomAnchor, constant: 20),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            progressView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 20),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24)
        ])
    }

    @objc private func close() {
        dismiss(animated: true)
    }

    func updateProgress(_ msg: String, _ p: Double) {
        statusLabel.text = msg
        progressView.setProgress(Float(p), animated: true)
    }

    func showError(_ msg: String) {
        spinner.stopAnimating()
        statusLabel.text = "分析失败\n\(msg)"
        statusLabel.textColor = .systemRed
    }
}
