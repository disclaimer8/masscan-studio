import Foundation

public struct PortResult: Codable, Identifiable, Hashable {
    public var ip: String
    public var port: Int
    public var proto: String
    public var discoveredAt: Date
    public var hostname: String?
    public var hostnameStatus: String?
    public var deviceHint: String?
    public var deviceEvidence: String?
    public var inspection: HostInspection?
    public var id: String { "\(ip):\(port)/\(proto)" }
    public var ipSort: UInt32 { ScanConfiguration.ipNumber(ip) ?? 0 }
    public var hostnameText: String { hostname ?? (hostnameStatus == "pending" ? "Looking up…" : "—") }
    public var deviceText: String { deviceHint ?? "Unknown" }
    public var inspectedService: InspectedService? {
        inspection?.services.first { $0.port == port }
    }
    public var serviceText: String {
        guard let detected = inspectedService, detected.state == "open", detected.method == "probed" else { return service }
        return detected.summary.isEmpty ? detected.name : detected.name + " · " + detected.summary
    }
    public var service: String {
        [21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
         110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
         1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
         5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt"][port] ?? "—"
    }
    public init(ip: String, port: Int, proto: String = "tcp", discoveredAt: Date = Date()) {
        self.ip = ip; self.port = port; self.proto = proto; self.discoveredAt = discoveredAt
    }
}
public struct ScanProgress {
    public var percent: Double
    public var packetsPerSecond: Double
    public var remaining: String
}
public enum OutputParser {
    private static let found = try! NSRegularExpression(pattern: #"^Discovered open port ([0-9]+)/([a-z]+) on ([0-9.]+)(?:\s|$)"#)
    private static let status = try! NSRegularExpression(pattern: #"rate:\s*([0-9.]+)-kpps,\s*([0-9.]+)% done,\s*(.*)"#)
    public static func result(_ line: String) -> PortResult? {
        guard let match = captures(found, line), let port = Int(match[0]),
              (1...65535).contains(port), ScanConfiguration.ipNumber(match[2]) != nil else { return nil }
        return PortResult(ip: match[2], port: port, proto: match[1])
    }
    public static func progress(_ line: String) -> ScanProgress? {
        guard let match = captures(status, line), let rate = Double(match[0]), let percent = Double(match[1]) else { return nil }
        let remaining = match[2].contains("waiting") ? "Receiving final replies" :
            (match[2].components(separatedBy: " remaining").first ?? "").trimmingCharacters(in: .whitespaces)
        return ScanProgress(percent: min(100, max(0, percent)), packetsPerSecond: rate * 1000, remaining: remaining)
    }
    public static func checkpoint(_ text: String) -> UInt64? {
        for line in text.components(separatedBy: .newlines) {
            let parts = line.components(separatedBy: "=").map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 && parts[0] == "resume-index" { return UInt64(parts[1]) }
        }
        return nil
    }
    private static func captures(_ regex: NSRegularExpression, _ line: String) -> [String]? {
        let text = line as NSString
        guard let match = regex.firstMatch(in: line, range: NSRange(location: 0, length: text.length)) else { return nil }
        return (1..<match.numberOfRanges).map { text.substring(with: match.range(at: $0)) }
    }
}
public struct LineFramer {
    private var buffer = Data()
    public init() {}
    public mutating func append(_ data: Data) -> [String] {
        buffer.append(data)
        var lines: [String] = []
        while let end = buffer.firstIndex(where: { $0 == 10 || $0 == 13 }) {
            let record = buffer[..<end]
            if !record.isEmpty { lines.append(String(decoding: record, as: UTF8.self)) }
            buffer.removeSubrange(...end)
        }
        if buffer.count > 1_048_576 { buffer.removeAll() }
        return lines
    }
    public mutating func finish() -> [String] {
        defer { buffer.removeAll() }
        return buffer.isEmpty ? [] : [String(decoding: buffer, as: UTF8.self)]
    }
}
public enum Export {
    public static func csv(_ rows: [PortResult]) -> String {
        let formatter = ISO8601DateFormatter()
        return "ip,port,protocol,service_hint,discovered_at,hostname,device_hint,device_evidence\r\n" + rows.map {
            [$0.ip, String($0.port), $0.proto, $0.service, formatter.string(from: $0.discoveredAt),
             $0.hostname ?? "", $0.deviceHint ?? "", $0.deviceEvidence ?? ""]
                .map(escape).joined(separator: ",")
        }.joined(separator: "\r\n") + (rows.isEmpty ? "" : "\r\n")
    }
    private static func escape(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let safe = trimmed.first.map { "=+-@".contains($0) } == true ? "'" + value : value
        return safe.contains(where: { ",\"\r\n".contains($0) }) ?
            "\"" + safe.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : safe
    }
}
public struct WireEvent: Codable {
    public var kind: String
    public var text: String?
    public var code: Int32?
    public init(_ kind: String, text: String? = nil, code: Int32? = nil) {
        self.kind = kind; self.text = text; self.code = code
    }
    public var line: Data {
        var data = (try? JSONEncoder().encode(self)) ?? Data()
        data.append(10)
        return data
    }
}
