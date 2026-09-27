import UIKit

/// 通用 UI 辅助与主题色
enum UITheme {
    static func riskColor(_ level: RiskLevel) -> UIColor {
        switch level {
        case .safe: return UIColor.systemGreen
        case .low: return UIColor.systemYellow
        case .suspicious: return UIColor.systemOrange
        case .malicious: return UIColor.systemRed
        }
    }

    static func riskColor(_ index: Int) -> UIColor {
        switch index {
        case 0: return UIColor.systemGreen
        case 1: return UIColor.systemYellow
        case 2: return UIColor.systemOrange
        default: return UIColor.systemRed
        }
    }

    static func formatBytes(_ bytes: Int) -> String {
        let b = Double(bytes)
        if b >= 1_073_741_824 { return String(format: "%.2f GB", b / 1_073_741_824) }
        if b >= 1_048_576 { return String(format: "%.2f MB", b / 1_048_576) }
        if b >= 1024 { return String(format: "%.1f KB", b / 1024) }
        return "\(bytes) B"
    }

    /// 创建带标题副标题的单元格样式
    static func makeLabel(_ text: String, size: CGFloat = 15, weight: UIFont.Weight = .regular) -> UILabel {
        let l = UILabel()
        l.text = text
        l.font = .systemFont(ofSize: size, weight: weight)
        l.numberOfLines = 0
        l.lineBreakMode = .byWordWrapping
        return l
    }

    static func riskBadge(_ level: RiskLevel) -> UIView {
        let v = UIView()
        v.backgroundColor = riskColor(level)
        v.layer.cornerRadius = 6
        v.clipsToBounds = true
        let l = makeLabel(level.label, size: 12, weight: .bold)
        l.textColor = .white
        l.textAlignment = .center
        l.translatesAutoresizingMaskIntoConstraints = false
        v.addSubview(l)
        NSLayoutConstraint.activate([
            l.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 8),
            l.trailingAnchor.constraint(equalTo: v.trailingAnchor, constant: -8),
            l.topAnchor.constraint(equalTo: v.topAnchor, constant: 3),
            l.bottomAnchor.constraint(equalTo: v.bottomAnchor, constant: -3)
        ])
        return v
    }
}
