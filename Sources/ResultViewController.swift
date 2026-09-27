import UIKit

/// 分析结果页：顶部卡片 + 分段页签 + 各详情子页
final class ResultViewController: UIViewController {
    let resultID: String
    private(set) var result: AnalysisResult!

    private let segmented = UISegmentedControl(items: ["概览", "权限", "Plist", "Mach-O", "字符串/URL", "依赖", "风险", "结构"])
    private let pageContainer = UIView()
    private var currentChild: UIViewController?

    init(resultID: String) {
        self.resultID = resultID
        super.init(nibName: nil, bundle: nil)
        self.result = SampleStore.shared.loadResult(id: resultID)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemGroupedBackground
        title = result?.plist.displayName.isEmpty == false ? result?.plist.displayName : (result?.fileName ?? "样本")
        let share = UIBarButtonItem(barButtonSystemItem: .action, target: self, action: #selector(shareTapped))
        let del = UIBarButtonItem(barButtonSystemItem: .trash, target: self, action: #selector(deleteTapped))
        navigationItem.rightBarButtonItems = [share, del]

        setupLayout()
        switchPage(0)
    }

    private func setupLayout() {
        segmented.selectedSegmentIndex = 0
        segmented.addTarget(self, action: #selector(segmentChanged), for: .valueChanged)
        segmented.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(segmented)

        pageContainer.translatesAutoresizingMaskIntoConstraints = false
        pageContainer.backgroundColor = .systemGroupedBackground
        view.addSubview(pageContainer)

        NSLayoutConstraint.activate([
            segmented.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            segmented.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            segmented.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),

            pageContainer.topAnchor.constraint(equalTo: segmented.bottomAnchor, constant: 4),
            pageContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            pageContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            pageContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }

    @objc private func segmentChanged() {
        switchPage(segmented.selectedSegmentIndex)
    }

    private func switchPage(_ index: Int) {
        currentChild?.view.removeFromSuperview()
        currentChild?.removeFromParent()
        let vc: UIViewController
        switch index {
        case 0: vc = OverviewDetailVC(result: result)
        case 1: vc = PermissionDetailVC(result: result)
        case 2: vc = PlistDetailVC(result: result)
        case 3: vc = MachODetailVC(result: result)
        case 4: vc = StringsDetailVC(result: result)
        case 5: vc = DepsDetailVC(result: result)
        case 6: vc = RiskDetailVC(result: result)
        default: vc = StructureDetailVC(result: result)
        }
        addChild(vc)
        vc.view.translatesAutoresizingMaskIntoConstraints = false
        pageContainer.addSubview(vc.view)
        NSLayoutConstraint.activate([
            vc.view.topAnchor.constraint(equalTo: pageContainer.topAnchor),
            vc.view.leadingAnchor.constraint(equalTo: pageContainer.leadingAnchor),
            vc.view.trailingAnchor.constraint(equalTo: pageContainer.trailingAnchor),
            vc.view.bottomAnchor.constraint(equalTo: pageContainer.bottomAnchor)
        ])
        vc.didMove(toParent: self)
        currentChild = vc
    }

    // MARK: - 操作

    @objc private func shareTapped() {
        guard let result = result else { return }
        let text = ReportExporter.markdown(result)
        var items: [Any] = [text]
        if let json = result.jsonData() {
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(result.fileName).analysis.json")
            try? json.write(to: tmp)
            items.append(tmp)
        }
        let ac = UIActivityViewController(activityItems: items, applicationActivities: nil)
        ac.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItems?.first
        present(ac, animated: true)
    }

    @objc private func deleteTapped() {
        let a = UIAlertController(title: "删除样本", message: "删除后不可恢复", preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "取消", style: .cancel))
        a.addAction(UIAlertAction(title: "删除", style: .destructive) { [weak self] _ in
            guard let self = self else { return }
            SampleStore.shared.delete(id: self.resultID)
            self.navigationController?.popViewController(animated: true)
        })
        present(a, animated: true)
    }
}
