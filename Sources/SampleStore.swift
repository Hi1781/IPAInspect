import UIKit
import Foundation

/// 样本本地存储：每次分析结果保存为 JSON 到 Documents/Samples，并在索引中登记。
final class SampleStore {
    static let shared = SampleStore()

    private let fm = FileManager.default
    private var samplesDir: URL {
        let dir = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Samples", isDirectory: true)
        if !fm.fileExists(atPath: dir.path) { try? fm.createDirectory(at: dir, withIntermediateDirectories: true) }
        return dir
    }
    private var indexURL: URL {
        fm.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("index.json")
    }

    struct Record: Codable {
        var id: String
        var fileName: String
        var sha256: String
        var score: Int
        var riskLevel: Int
        var analyzedAt: String
        var fileSize: Int
        var bundleID: String
        var appName: String
    }

    private(set) var records: [Record] = []

    init() { loadIndex() }

    func allRecords() -> [Record] { records }

    func record(forID id: String) -> Record? { records.first { $0.id == id } }

    func loadResult(id: String) -> AnalysisResult? {
        let url = samplesDir.appendingPathComponent("\(id).json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(AnalysisResult.self, from: data)
    }

    @discardableResult
    func save(_ result: AnalysisResult) -> String {
        let id = result.sha256.prefix(16)
        let idStr = String(id)
        let url = samplesDir.appendingPathComponent("\(idStr).json")
        if let json = result.jsonData() { try? json.write(to: url) }
        let rec = Record(id: idStr, fileName: result.fileName,
                         sha256: result.sha256,
                         score: result.score,
                         riskLevel: result.riskLevel.rawValue,
                         analyzedAt: result.analyzedAt,
                         fileSize: result.fileSize,
                         bundleID: result.plist.bundleID,
                         appName: result.plist.displayName.isEmpty ? result.plist.name : result.plist.displayName)
        if let idx = records.firstIndex(where: { $0.id == idStr }) {
            records[idx] = rec
        } else {
            records.insert(rec, at: 0)
        }
        saveIndex()
        return idStr
    }

    func delete(id: String) {
        records.removeAll { $0.id == id }
        try? fm.removeItem(at: samplesDir.appendingPathComponent("\(id).json"))
        saveIndex()
    }

    private func loadIndex() {
        guard let data = try? Data(contentsOf: indexURL),
              let recs = try? JSONDecoder().decode([Record].self, from: data) else { return }
        records = recs
    }

    private func saveIndex() {
        let enc = JSONEncoder()
        if let data = try? enc.encode(records) { try? data.write(to: indexURL) }
    }
}
