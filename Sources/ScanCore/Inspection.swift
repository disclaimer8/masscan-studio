import Foundation
import Darwin

public struct InspectionRequest {
    public let ip: String
    public let ports: [Int]
    public init(ip: String, ports: [Int]) { self.ip = ip; self.ports = ports }
    public var probePorts: [Int] { Array(Set(ports).subtracting([9100])).sorted() }
    public func arguments() throws -> [String] {
        guard ScanConfiguration.ipNumber(ip) != nil else { throw ScanError("Select one IPv4 host.") }
        guard !ports.isEmpty, ports.allSatisfy({ (1...65535).contains($0) }),
              Set(ports).count <= 64 else { throw ScanError("Detailed checks support 1–64 discovered TCP ports per host.") }
        guard !probePorts.isEmpty else { throw ScanError("Port 9100 is a raw printing port and is excluded from service probes.") }
        return ["--unprivileged", "-sT", "-sV", "--version-light", "-Pn", "-n",
                "--host-timeout", "45s", "--max-retries", "1", "-T3",
                "-p", probePorts.map(String.init).joined(separator: ","), "-oX", "-", ip]
    }
}
public struct InspectedService: Codable, Hashable, Identifiable {
    public var port: Int
    public var state = "unknown"
    public var name = "unknown"
    public var product = ""
    public var version = ""
    public var extraInfo = ""
    public var tunnel = ""
    public var deviceType = ""
    public var osType = ""
    public var reportedHostname = ""
    public var method = ""
    public var confidence = ""
    public var cpes: [String] = []
    public var id: Int { port }
    public var summary: String { [product, version, extraInfo].filter { !$0.isEmpty }.joined(separator: " · ") }
}
public struct HostInspection: Codable, Hashable {
    public var ip: String
    public var date = Date()
    public var ports: [Int]
    public var services: [InspectedService]
    public var deviceGuess: DeviceGuess? {
        let detected = services.filter { $0.state == "open" && $0.method == "probed" }
        let typed = detected.filter { !$0.deviceType.isEmpty }
        let types = Set(typed.map(\.deviceType)).sorted()
        if !types.isEmpty {
            let evidence = typed.map { "TCP \($0.port): \($0.summary.isEmpty ? $0.name : $0.summary) reports device type \($0.deviceType)." }.joined(separator: "\n")
            return DeviceGuess(label: "Possible " + types.joined(separator: " / "),
                               evidence: evidence + "\nSource: Nmap service response matching. This is an estimate, not verified hardware.")
        }
        let os = Set(detected.map(\.osType).filter { !$0.isEmpty }).sorted()
        if !os.isEmpty {
            return DeviceGuess(label: "Possible " + os.joined(separator: " / ") + " host",
                               evidence: detected.filter { !$0.osType.isEmpty }.map { "TCP \($0.port): \($0.summary) suggests \($0.osType)." }.joined(separator: "\n") +
                               "\nSource: service responses; no OS fingerprint scan was performed.")
        }
        return nil
    }
}
public enum InspectionParser {
    public static func parse(_ data: Data, request: InspectionRequest) throws -> HostInspection {
        guard data.count <= 2_097_152 else { throw ScanError("Device response exceeded the size limit.") }
        let text = String(decoding: data, as: UTF8.self)
        guard !text.localizedCaseInsensitiveContains("<!ENTITY") else { throw ScanError("Unsupported XML entity.") }
        let delegate = NmapXML(request: request)
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse(), delegate.success, delegate.hostMatched, !delegate.timedOut else {
            throw ScanError(delegate.timedOut ? "The device check timed out. The host may not answer service probes." :
                            "Nmap did not return a complete result for this host.")
        }
        return HostInspection(ip: request.ip, ports: request.probePorts, services: delegate.services.sorted { $0.port < $1.port })
    }
}
private final class NmapXML: NSObject, XMLParserDelegate {
    let request: InspectionRequest
    var hostMatched = false, success = false, timedOut = false
    var services: [InspectedService] = []
    private var inHost = false, matches = false, inCPE = false
    private var current: InspectedService?
    private var hostServices: [InspectedService] = []
    private var cpe = ""
    init(request: InspectionRequest) { self.request = request }
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes a: [String: String]) {
        switch elementName {
        case "host":
            inHost = true; matches = false; hostServices = []
            if a["timedout"] == "true" { timedOut = true }
        case "address" where inHost:
            if a["addrtype"] == "ipv4", a["addr"] == request.ip { matches = true }
        case "port" where inHost:
            if a["protocol"] == "tcp", let port = a["portid"].flatMap(Int.init), request.probePorts.contains(port) {
                current = InspectedService(port: port)
            } else { current = nil }
        case "state": current?.state = clean(a["state"])
        case "service":
            current?.name = clean(a["name"]); current?.product = clean(a["product"])
            current?.version = clean(a["version"]); current?.extraInfo = clean(a["extrainfo"])
            current?.tunnel = clean(a["tunnel"]); current?.deviceType = clean(a["devicetype"])
            current?.osType = clean(a["ostype"]); current?.reportedHostname = clean(a["hostname"])
            current?.method = clean(a["method"]); current?.confidence = clean(a["conf"])
        case "cpe": inCPE = true; cpe = ""
        case "finished": success = a["exit"] == "success"
        default: break
        }
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if inCPE, cpe.count < 2048 { cpe += String(string.prefix(2048 - cpe.count)) }
    }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        switch elementName {
        case "cpe": inCPE = false; current?.cpes.append(clean(cpe))
        case "port": if let current { hostServices.append(current) }; current = nil
        case "host":
            if matches { hostMatched = true; services = hostServices }
            inHost = false
        default: break
        }
    }
    private func clean(_ text: String?) -> String {
        String((text ?? "").unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(1024).map(Character.init))
    }
}
public enum WebsiteLink {
    public static func validHostname(_ raw: String?) -> String? {
        guard var name = raw, !name.isEmpty else { return nil }
        if name.hasSuffix(".") { name.removeLast() }
        guard name.utf8.count <= 253, !name.isEmpty else { return nil }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ label in
            !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
            label.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }) else { return nil }
        return name
    }
    public static func url(for row: PortResult, hostRows: [PortResult]) -> URL? {
        guard ScanConfiguration.ipNumber(row.ip) != nil else { return nil }
        let peers = hostRows.filter { $0.ip == row.ip && $0.proto == "tcp" }
        let hostname = validHostname(row.hostname)
        let preferred = [443, 80, 8443, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 5001, 9000, 9443, 10000]
        func scheme(_ port: Int) -> String? {
            if let service = peers.compactMap(\.inspection).flatMap(\.services).first(where: { $0.port == port && $0.state == "open" && $0.method == "probed" }) {
                guard service.name == "http" || service.name == "https" || service.name.hasPrefix("http-") else { return nil }
                return service.tunnel == "ssl" || service.name == "https" ? "https" : "http"
            }
            guard preferred.contains(port) else { return nil }
            return [443, 8443, 5001, 9443].contains(port) ? "https" : "http"
        }
        let chosen: Int?
        if scheme(row.port) != nil { chosen = row.port }
        else { chosen = (preferred + peers.map(\.port).sorted()).first { port in peers.contains { $0.port == port } && scheme(port) != nil } }
        guard chosen != nil || hostname != nil else { return nil }
        var components = URLComponents()
        components.scheme = chosen.flatMap(scheme) ?? "https"
        components.host = hostname ?? row.ip
        if let chosen, !(chosen == 80 && components.scheme == "http"), !(chosen == 443 && components.scheme == "https") {
            components.port = chosen
        }
        components.path = "/"
        return components.url
    }
}
