import UIKit

/// 分析结果页：顶部等分横铺页签栏（选中词条变宽）+ 各详情子页
final class ResultViewController: UIViewController {
    let resultID: String
    private(set) var result: AnalysisResult!

    private let tabTitles = ["概览", "权限", "Plist", "MachO", "字符串", "依赖", "风险", "结构", "签名", "动态分析"]
    private let tabBar = UIStackView()
    private var tabButtons: [UIButton] = []
    private var tabWidths: [NSLayoutConstraint] = []
    private var selectedIndex = 0
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
        tabBar.axis = .horizontal
        tabBar.spacing = 5
        tabBar.distribution = .fill
        tabBar.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tabBar)

        for (i, title) in tabTitles.enumerated() {
            let b = UIButton(type: .system)
            b.setTitle(title, for: .normal)
            b.titleLabel?.font = .systemFont(ofSize: 13, weight: .medium)
            b.titleLabel?.adjustsFontSizeToFitWidth = true
            b.titleLabel?.minimumScaleFactor = 0.5
            b.tag = i
            b.layer.cornerRadius = 15
            b.contentEdgeInsets = UIEdgeInsets(top: 7, left: 4, bottom: 7, right: 4)
            b.addTarget(self, action: #selector(tabTapped(_:)), for: .touchUpInside)
            let wc = b.widthAnchor.constraint(equalToConstant: 1)
            wc.isActive = true
            tabButtons.append(b)
            tabWidths.append(wc)
            tabBar.addArrangedSubview(b)
        }

        pageContainer.translatesAutoresizingMaskIntoConstraints = false
        pageContainer.backgroundColor = .systemGroupedBackground
        view.addSubview(pageContainer)

        NSLayoutConstraint.activate([
            tabBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 6),
            tabBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            tabBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            tabBar.heightAnchor.constraint(equalToConstant: 44),

            pageContainer.topAnchor.constraint(equalTo: tabBar.bottomAnchor, constant: 2),
            pageContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            pageContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            pageContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if tabBar.bounds.width > 0 {
            layoutTabWidths(selected: selectedIndex)
        }
    }

    /// 等分横铺 + 选中词条变宽（手风琴），总宽恒等于可用宽度
    private func layoutTabWidths(selected: Int, animated: Bool = false) {
        let total = tabBar.bounds.width - tabBar.spacing * CGFloat(tabButtons.count - 1)
        guard total > 0, !tabWidths.isEmpty else { return }
        let n = CGFloat(tabWidths.count)
        let inactiveW = max(total / (n + 1.2), 30)       // 选中项额外多占 ~20% 总量
        let selectedW = total - inactiveW * (n - 1)
        for (i, c) in tabWidths.enumerated() {
            c.constant = (i == selected) ? max(selectedW, inactiveW) : inactiveW
        }
        if animated {
            UIView.animate(withDuration: 0.22) { self.view.layoutIfNeeded() }
        } else {
            view.layoutIfNeeded()
        }
    }

    @objc private func tabTapped(_ sender: UIButton) {
        selectTab(sender.tag)
    }

    private func selectTab(_ index: Int) {
        selectedIndex = index
        for (i, b) in tabButtons.enumerated() {
            let selected = i == index
            b.backgroundColor = selected ? .systemIndigo : .secondarySystemGroupedBackground
            b.setTitleColor(selected ? .white : .label, for: .normal)
            b.tintColor = .clear
        }
        layoutTabWidths(selected: index, animated: true)
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
