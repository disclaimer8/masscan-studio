import Foundation
import Darwin
import dnssd
public struct DeviceGuess: Equatable {
    public var label: String
    public var evidence: String
    public init(label: String, evidence: String) { self.label = label; self.evidence = evidence }
}
public enum DeviceHints {
    public static func infer(hostname: String?, ports: Set<Int>) -> DeviceGuess? {
        let words = Set((hostname ?? "").lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init))
        let names: [(Set<String>, String)] = [
            (["macbook", "imac", "macmini", "macstudio"], "Possible Mac"),
            (["iphone", "ipad"], "Possible iPhone / iPad"),
            (["synology", "diskstation", "qnap", "nas"], "Possible NAS"),
            (["printer", "laserjet", "officejet", "epson", "brother"], "Possible printer"),
            (["router", "gateway", "openwrt", "mikrotik"], "Possible router"),
            (["raspberrypi", "raspberry"], "Possible Raspberry Pi")
        ]
        for (tokens, label) in names {
            if let token = words.intersection(tokens).sorted().first {
                return DeviceGuess(label: label, evidence: "The reported hostname contains “\(token)”. Names can be changed; model and OS are not verified.")
            }
        }
        let printing = ports.intersection([515, 631, 9100]).sorted()
        if !printing.isEmpty {
            return DeviceGuess(label: "Possible printer", evidence: "Open TCP \(printing.map(String.init).joined(separator: ", ")) is commonly used for printing. It may also be a print server.")
        }
        if ports.contains(3389) {
            return DeviceGuess(label: "RDP host", evidence: "TCP 3389 is open. Often Remote Desktop; this does not confirm Windows or the device model.")
        }
        if ports.contains(445) && ports.contains(2049) {
            return DeviceGuess(label: "Possible file server", evidence: "TCP 445 and 2049 are open, commonly associated with SMB and NFS.")
        }
        if ports.contains(554) {
            return DeviceGuess(label: "Possible camera / media", evidence: "TCP 554 is open, commonly associated with RTSP streaming. It may be a camera or a media server.")
        }
        return nil
    }
}
public enum DNSName {
    public static func reverseQuery(_ ip: String) -> String? {
        guard ScanConfiguration.ipNumber(ip) != nil else { return nil }
        return ip.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa."
    }
    public static func decodePTR(_ bytes: [UInt8]) -> String? {
        var labels: [String] = []
        var offset = 0
        while offset < bytes.count {
            let length = Int(bytes[offset]); offset += 1
            if length == 0 {
                let name = labels.joined(separator: ".")
                return offset == bytes.count && !name.isEmpty && name.utf8.count <= 253 ? name : nil
            }
            // DNS-SD returns uncompressed RDATA. Reject pointers and malformed labels.
            guard length <= 63, offset + length < bytes.count else { return nil }
            let label = bytes[offset..<(offset + length)]
            guard label.allSatisfy({ (33...126).contains($0) && $0 != 46 }),
                  let text = String(bytes: label, encoding: .utf8) else { return nil }
            labels.append(text); offset += length
        }
        return nil
    }
}

private final class QueryResult {
    var hostname: String?
    var done = false
}

/// Uses the macOS DNS/mDNS responder. Every query is cancelled at its deadline.
public enum ReverseDNS {
    public static func lookup(_ ip: String, timeout: TimeInterval = 3) -> String? {
        guard let query = DNSName.reverseQuery(ip), timeout > 0 else { return nil }
        let result = QueryResult()
        var service: DNSServiceRef?
        let error = DNSServiceQueryRecord(
            &service, 0, 0, query, UInt16(kDNSServiceType_PTR), UInt16(kDNSServiceClass_IN),
            { _, flags, _, error, _, type, _, length, data, _, context in
                guard let context else { return }
                let result = Unmanaged<QueryResult>.fromOpaque(context).takeUnretainedValue()
                if error != kDNSServiceErr_NoError { result.done = true; return }
                guard flags & UInt32(kDNSServiceFlagsAdd) != 0, type == UInt16(kDNSServiceType_PTR),
                      let data else { return }
                let bytes = Array(UnsafeBufferPointer(start: data.assumingMemoryBound(to: UInt8.self), count: Int(length)))
                if let name = DNSName.decodePTR(bytes) { result.hostname = name; result.done = true }
            }, Unmanaged.passUnretained(result).toOpaque())
        guard error == kDNSServiceErr_NoError, let service else { return nil }
        defer { DNSServiceRefDeallocate(service) }
        let fd = DNSServiceRefSockFD(service)
        guard fd >= 0 else { return nil }
        let deadline = ProcessInfo.processInfo.systemUptime + min(timeout, 10)
        while !result.done {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining <= 0 { break }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, Int32(min(remaining * 1000, 100)))
            if ready < 0 { if errno == EINTR { continue }; break }
            if ready > 0 {
                guard descriptor.revents & Int16(POLLIN) != 0,
                      DNSServiceProcessResult(service) == kDNSServiceErr_NoError else { break }
            }
        }
        return result.hostname
    }
}

public final class HostnameResolver {
    private let queue: OperationQueue = {
        let queue = OperationQueue()
        queue.name = "MasscanStudio.ReverseDNS"
        queue.maxConcurrentOperationCount = 4
        queue.qualityOfService = .utility
        return queue
    }()
    public init() {}
    public func resolve(_ ip: String, completion: @escaping (String?) -> Void) {
        queue.addOperation {
            let result = ReverseDNS.lookup(ip)
            DispatchQueue.main.async { completion(result) }
        }
    }
}
