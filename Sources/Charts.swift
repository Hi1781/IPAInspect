import UIKit

/// 环形饼图：用于权限分布 / 风险分级分布
final class PieChartView: UIView {
    struct Slice { var value: Double; var color: UIColor; var label: String }

    var slices: [Slice] = [] {
        didSet { setNeedsDisplay() }
    }

    private let titleLabel: UILabel

    init(title: String) {
        titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        titleLabel.textColor = .secondaryLabel
        super.init(frame: .zero)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleLabel)
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: topAnchor),
            titleLabel.centerXAnchor.constraint(equalTo: centerXAnchor)
        ])
        backgroundColor = .clear
    }

    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }
        let side = rect.width * 0.55
        let center = CGPoint(x: rect.width / 2, y: rect.height / 2 + 12)
        let radius = side / 2
        let lineW: CGFloat = min(28, radius * 0.4)
        let ringR = radius - lineW / 2

        let total = slices.reduce(0) { $0 + $1.value }
        guard total > 0 else {
            ctx.setStrokeColor(UIColor.systemGray3.cgColor)
            ctx.setLineWidth(lineW)
            ctx.addArc(center: center, radius: ringR, startAngle: 0, endAngle: .pi * 2, clockwise: false)
            ctx.strokePath()
            return
        }
        var start: CGFloat = -.pi / 2
        for s in slices where s.value > 0 {
            let angle = CGFloat(s.value / total) * .pi * 2
            ctx.setStrokeColor(s.color.cgColor)
            ctx.setLineWidth(lineW)
            ctx.addArc(center: center, radius: ringR, startAngle: start, endAngle: start + angle, clockwise: false)
            ctx.strokePath()
            start += angle
        }
        ctx.setFillColor(UIColor.label.cgColor)
        let centerText = String(format: "%.0f", total) as NSString
        let attrs: [NSAttributedString.Key: Any] = [.font: UIFont.systemFont(ofSize: 15, weight: .bold),
                                                    .foregroundColor: UIColor.label]
        let size = centerText.size(withAttributes: attrs)
        centerText.draw(at: CGPoint(x: center.x - size.width / 2, y: center.y - size.height / 2),
                        withAttributes: attrs)

        // 图例
        var y = rect.height - CGFloat(slices.count) * 18 - 4
        for s in slices {
            ctx.setFillColor(s.color.cgColor)
            ctx.fillEllipse(in: CGRect(x: rect.width * 0.2, y: y + 4, width: 10, height: 10))
            let text = "\(s.label) ×\(Int(s.value))" as NSString
            (text as NSString).draw(at: CGPoint(x: rect.width * 0.2 + 16, y: y),
                                    withAttributes: [.font: UIFont.systemFont(ofSize: 12),
                                                     .foregroundColor: UIColor.secondaryLabel])
            y += 18
        }
    }
}

/// 风险分数条（0~100）
final class ScoreBarView: UIView {
    var score: Int = 0 { didSet { setNeedsDisplay() } }
    private let titleLabel: UILabel

    init() {
        titleLabel = UILabel()
        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        titleLabel.textColor = .secondaryLabel
        super.init(frame: .zero)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleLabel)
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: topAnchor),
            titleLabel.centerXAnchor.constraint(equalTo: centerXAnchor)
        ])
        backgroundColor = .clear
        titleLabel.text = "风险评分"
    }

    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }
        let track = CGRect(x: rect.width * 0.15, y: rect.height / 2 + 10,
                           width: rect.width * 0.7, height: 12)
        ctx.setFillColor(UIColor.systemGray5.cgColor)
        let r = track.height / 2
        let path = UIBezierPath(roundedRect: track, cornerRadius: r)
        ctx.addPath(path.cgPath)
        ctx.fillPath()

        let color = UITheme.riskColor(RiskLevel.fromScore(score))
        let fillW = track.width * CGFloat(score) / 100.0
        if fillW > 1 {
            let fill = CGRect(x: track.minX, y: track.minY, width: fillW, height: track.height)
            ctx.setFillColor(color.cgColor)
            let p2 = UIBezierPath(roundedRect: fill, cornerRadius: r)
            ctx.addPath(p2.cgPath)
            ctx.fillPath()
        }
        let label = "\(score) / 100" as NSString
        (label).draw(at: CGPoint(x: rect.width / 2 - 24, y: rect.height / 2 - 8),
                     withAttributes: [.font: UIFont.systemFont(ofSize: 12, weight: .bold),
                                      .foregroundColor: UIColor.label])
    }
}

/// 水平条列表：类别 + 数量
final class BarRowView: UIView {
    private var items: [(String, Int, UIColor)] = []

    init(items: [(String, Int, UIColor)]) {
        self.items = items
        super.init(frame: .zero)
        backgroundColor = .clear
        let h = CGFloat(items.count) * 42 + 8
        heightAnchor.constraint(equalToConstant: h).isActive = true
    }
    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        subviews.forEach { $0.removeFromSuperview() }
        let total = items.reduce(0) { $0 + $1.1 }
        var y: CGFloat = 4
        for (label, value, color) in items {
            let row = UIView()
            let name = UITheme.makeLabel("\(label)  \(value)", size: 13)
            name.translatesAutoresizingMaskIntoConstraints = false
            row.addSubview(name)
            let trackH: CGFloat = 8
            let track = UIView()
            track.backgroundColor = .systemGray5
            track.layer.cornerRadius = trackH / 2
            track.translatesAutoresizingMaskIntoConstraints = false
            row.addSubview(track)
            let fill = UIView()
            fill.backgroundColor = color
            fill.layer.cornerRadius = trackH / 2
            fill.translatesAutoresizingMaskIntoConstraints = false
            track.addSubview(fill)
            NSLayoutConstraint.activate([
                name.topAnchor.constraint(equalTo: row.topAnchor),
                name.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 12),
                name.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -12),
                track.topAnchor.constraint(equalTo: name.bottomAnchor, constant: 4),
                track.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 12),
                track.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -12),
                track.heightAnchor.constraint(equalToConstant: trackH),
                track.bottomAnchor.constraint(equalTo: row.bottomAnchor, constant: -8),
                fill.leadingAnchor.constraint(equalTo: track.leadingAnchor),
                fill.topAnchor.constraint(equalTo: track.topAnchor),
                fill.bottomAnchor.constraint(equalTo: track.bottomAnchor),
                fill.widthAnchor.constraint(equalTo: track.widthAnchor,
                                            multiplier: total > 0 ? CGFloat(value) / CGFloat(total) : 0)
            ])
            row.translatesAutoresizingMaskIntoConstraints = false
            addSubview(row)
            NSLayoutConstraint.activate([
                row.topAnchor.constraint(equalTo: topAnchor, constant: y),
                row.leadingAnchor.constraint(equalTo: leadingAnchor),
                row.trailingAnchor.constraint(equalTo: trailingAnchor)
            ])
            y += 42
        }
    }
}
