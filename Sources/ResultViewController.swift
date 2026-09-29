import UIKit

/// 分析结果页：顶部可滚动页签栏 + 各详情子页
final class ResultViewController: UIViewController {
    let resultID: String
    private(set) var result: AnalysisResult!

    private let tabTitles = ["概览", "权限", "Plist", "MachO", "字符串", "依赖", "风险", "结构", "签名", "动态分析"]
    private let tabScroll = UIScrollView()
    private let tabStack = UIStackView()
    private var tabButtons: [UIButton] = []
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
        selectTab(0)
    }

    private func setupLayout() {
        tabScroll.showsHorizontalScrollIndicator = false
        tabScroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tabScroll)

        tabStack.axis = .horizontal
        tabStack.spacing = 6
        tabStack.translatesAutoresizingMaskIntoConstraints = false
        tabScroll.addSubview(tabStack)

        for (i, title) in tabTitles.enumerated() {
            let b = UIButton(type: .system)
            b.setTitle(title, for: .normal)
            b.titleLabel?.font = .systemFont(ofSize: 13, weight: .medium)
            b.tag = i
            b.layer.cornerRadius = 18
            b.contentEdgeInsets = UIEdgeInsets(top: 8, left: 22, bottom: 8, right: 22)
            b.addTarget(self, action: #selector(tabTapped(_:)), for: .touchUpInside)
            tabButtons.append(b)
            tabStack.addArrangedSubview(b)
        }

        pageContainer.translatesAutoresizingMaskIntoConstraints = false
        pageContainer.backgroundColor = .systemGroupedBackground
        view.addSubview(pageContainer)

        NSLayoutConstraint.activate([
            tabScroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 4),
            tabScroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tabScroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tabScroll.heightAnchor.constraint(equalToConstant: 48),

            tabStack.topAnchor.constraint(equalTo: tabScroll.contentLayoutGuide.topAnchor),
            tabStack.leadingAnchor.constraint(equalTo: tabScroll.contentLayoutGuide.leadingAnchor, constant: 12),
            tabStack.trailingAnchor.constraint(equalTo: tabScroll.contentLayoutGuide.trailingAnchor, constant: -12),
            tabStack.bottomAnchor.constraint(equalTo: tabScroll.contentLayoutGuide.bottomAnchor),
            tabStack.heightAnchor.constraint(equalTo: tabScroll.frameLayoutGuide.heightAnchor),

            pageContainer.topAnchor.constraint(equalTo: tabScroll.bottomAnchor, constant: 2),
            pageContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            pageContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            pageContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }

    @objc private func tabTapped(_ sender: UIButton) {
        selectTab(sender.tag)
    }

    private func selectTab(_ index: Int) {
        for (i, b) in tabButtons.enumerated() {
            let selected = i == index
            b.backgroundColor = selected ? .systemIndigo : .secondarySystemGroupedBackground
            b.setTitleColor(selected ? .white : .label, for: .normal)
            b.tintColor = .clear
        }
        switchPage(index)
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
        case 7: vc = StructureDetailVC(result: result)
        case 8: vc = SignDetailVC(result: result)
        default: vc = DynamicAnalysisDetailVC(result: result)
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
        // 滚动到所选页签可见
        if index < tabButtons.count {
            let target = tabButtons[index]
            tabScroll.scrollRectToVisible(target.convert(target.bounds, to: tabScroll), animated: true)
        }
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
