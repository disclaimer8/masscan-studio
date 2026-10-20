import Foundation
public struct ScanConfiguration: Codable, Equatable {
    public var targets = ""
    public var ports = "22,80,443"
    public var exclusions = ""
    public var interface = ""
    public var rate = 100
    public var seed: UInt64 = UInt64.random(in: 1...UInt64(UInt32.max))
    public var resumeIndex: UInt64?
    // Optional for backward compatibility with v0.1 history and profiles.
    public var resolveHostnames: Bool? = true
    public init() {}
    public func arguments() throws -> [String] {
        let hosts = Self.tokens(targets)
        guard !hosts.isEmpty else { throw ScanError("Enter at least one IPv4 address or range.") }
        guard hosts.count <= 4096, targets.utf8.count < 65536 else { throw ScanError("Too many targets for one profile.") }
        for host in hosts + Self.tokens(exclusions) {
            guard Self.validRange(host) else { throw ScanError("Invalid IPv4 target: \(host)") }
        }
        let portTokens = Self.tokens(ports)
        guard !portTokens.isEmpty else { throw ScanError("Enter TCP ports, such as 22,80,443.") }
        for port in portTokens {
            let parts = port.split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(parts.count),
                  parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isASCIIWholeNumber) }),
                  let first = Int(parts[0]), (1...65535).contains(first),
                  let last = Int(parts.last!), (first...65535).contains(last)
            else { throw ScanError("Invalid TCP port or range: \(port)") }
        }
        guard (1...10_000_000).contains(rate) else { throw ScanError("Rate must be between 1 and 10,000,000 packets/s.") }
        guard interface.isEmpty || (interface.count <= 32 && interface.first!.isLetter &&
              interface.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-") }))
        else { throw ScanError("Invalid network interface name.") }
        // Explicit interactive output works with Homebrew masscan 1.3.2.
        var args = hosts + ["-p", portTokens.joined(separator: ","), "--rate", String(rate),
                            "--wait", "3", "--seed", String(seed), "--interactive",
                            "--output-format", "interactive"]
        if !exclusions.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            args += ["--exclude", Self.tokens(exclusions).joined(separator: ",")]
        }
        if !interface.isEmpty { args += ["-e", interface] }
        if let resumeIndex { args += ["--resume-index", String(resumeIndex)] }
        return args
    }
    public static func tokens(_ text: String) -> [String] {
        text.split(whereSeparator: { $0.isWhitespace || $0 == "," }).map(String.init)
    }
    public static func ipNumber(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3, part.allSatisfy(\.isASCIIWholeNumber),
                  let byte = UInt32(part), byte <= 255 else { return nil }
            result = (result << 8) | byte
        }
        return result
    }
    public static func validRange(_ text: String) -> Bool {
        if text.contains("/") {
            let parts = text.split(separator: "/", omittingEmptySubsequences: false)
            return parts.count == 2 && ipNumber(String(parts[0])) != nil &&
                !parts[1].isEmpty && parts[1].allSatisfy(\.isASCIIWholeNumber) &&
                Int(parts[1]).map { (0...32).contains($0) } == true
        }
        if text.contains("-") {
            let parts = text.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count == 2, let first = ipNumber(String(parts[0])),
                  let last = ipNumber(String(parts[1])) else { return false }
            return first <= last
        }
        return ipNumber(text) != nil
    }
    public var preview: String {
        (try? (["masscan"] + arguments()).map(shellQuote).joined(separator: " ")) ?? "Complete the scan settings to see the command."
    }
}
private extension Character {
    var isASCIIWholeNumber: Bool { isASCII && isNumber }
}
public struct ScanError: LocalizedError {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}
public func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}
public func appleScriptQuote(_ value: String) -> String {
    "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r") + "\""
}
public enum MasscanBinary {
    public static var path: String? {
        ["/opt/homebrew/bin/masscan", "/usr/local/bin/masscan"].first {
            FileManager.default.isExecutableFile(atPath: $0)
        }
    }
}
