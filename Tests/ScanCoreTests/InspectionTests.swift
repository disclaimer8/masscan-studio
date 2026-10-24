import XCTest
@testable import ScanCore

/// Loopback HTTP fixture: answers every connection with one fixed HTML page.
private final class LocalHTTPFixture {
    let port: Int
    private let listener: Int32
    private var running = true
    private let lock = NSLock()

    init() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ScanError("fixture socket") }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, size) }
        }
        guard bound == 0, Darwin.listen(fd, 8) == 0 else { close(fd); throw ScanError("fixture bind") }
        var length = size
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        port = Int(UInt16(bigEndian: address.sin_port))
        listener = fd
        Thread.detachNewThread { [self] in serve() }
    }

    private func serve() {
        // nmap only names the service when the banner is one it knows: advertise a common server.
        let body = "<html><title>Local fixture</title></html>"
        let response = Data("HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)".utf8)
        while true {
            let client = accept(listener, nil, nil)
            lock.lock(); let stop = !running; lock.unlock()
            if client < 0 || stop { if client >= 0 { close(client) }; close(listener); return }
            var quiet: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &quiet, socklen_t(MemoryLayout<Int32>.size))
            var timeout = timeval(tv_sec: 10, tv_usec: 0)
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var request = [UInt8](repeating: 0, count: 4096)
            // Like a real server, stay silent for a client that sends nothing (nmap's NULL probe).
            if recv(client, &request, request.count, 0) > 0 {
                response.withUnsafeBytes { _ = send(client, $0.baseAddress, response.count, 0) }
            }
            close(client)
        }
    }

    func stop() {
        lock.lock(); running = false; lock.unlock()
        // Wake the blocked accept with one throwaway connection, then release the port.
        let wake = socket(AF_INET, SOCK_STREAM, 0)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(wake, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        close(wake)
    }
}

final class InspectionTests: XCTestCase {
    func testRealNmapInspectsLocalHTTPWithoutAdministrator() throws {
        guard ServiceInspector.binary != nil else { throw XCTSkip("Nmap not installed") }
        let server = try LocalHTTPFixture()
        defer { server.stop() }
        let port = server.port
        let report = try ServiceInspector().run(InspectionRequest(ip: "127.0.0.1", ports: [port]))
        XCTAssertEqual(report.services.first?.state, "open")
        XCTAssertEqual(report.services.first?.name, "http")
        XCTAssertEqual(report.services.first?.method, "probed")
    }
    func testRunnerDeadlineAndCancellationStopOwnedProcess() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("slow-fixture")
        try "#!/bin/sh\nexec /bin/sleep 20\n".write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let request = InspectionRequest(ip: "127.0.0.1", ports: [80])
        let start = Date()
        XCTAssertThrowsError(try ServiceInspector().run(request, executable: executable, deadline: 0.1)) {
            XCTAssertTrue($0.localizedDescription.contains("timed out"))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 4)
        let worker = ServiceInspector(), stopped = expectation(description: "Cancelled process exits")
        DispatchQueue.global().async {
            do {
                _ = try worker.run(request, executable: executable)
                XCTFail("Expected cancellation")
            } catch {
                XCTAssertTrue(error.localizedDescription.contains("cancelled"))
            }
            stopped.fulfill()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) { worker.cancel() }
        wait(for: [stopped], timeout: 4)
    }
    func testWebsiteLinksUseWebPortAndRejectURLSyntaxInDNS() {
        var row = PortResult(ip: "192.0.2.1", port: 8443)
        row.hostname = "camera.example."
        XCTAssertEqual(WebsiteLink.url(for: row, hostRows: [row])?.absoluteString, "https://camera.example:8443/")
        row.port = 22
        let web = PortResult(ip: row.ip, port: 8080)
        XCTAssertEqual(WebsiteLink.url(for: row, hostRows: [row, web])?.absoluteString, "http://camera.example:8080/")
        row.hostname = "evil.example/path?x=1"
        XCTAssertEqual(WebsiteLink.url(for: row, hostRows: [row, web])?.absoluteString, "http://192.0.2.1:8080/")
        row.hostname = nil
        XCTAssertNil(WebsiteLink.url(for: row, hostRows: [row]))
        row.hostname = "host.example"
        XCTAssertEqual(WebsiteLink.url(for: row, hostRows: [row])?.absoluteString, "https://host.example/")
        for invalid in ["evil.example@localhost", "host:8080", "bad..name", "-bad.example", "host\n.example"] {
            XCTAssertNil(WebsiteLink.validHostname(invalid))
        }
    }
    func testInspectionScopeIsOneIPv4AndKnownPortsOnly() throws {
        let args = try InspectionRequest(ip: "192.0.2.1", ports: [443, 22, 22, 9100]).arguments()
        XCTAssertEqual(args.last, "192.0.2.1")
        let portIndex = try XCTUnwrap(args.firstIndex(of: "-p"))
        XCTAssertEqual(args[portIndex + 1], "22,443")
        XCTAssertTrue(args.contains("--version-light"))
        XCTAssertFalse(args.contains("--allports"))
        XCTAssertFalse(args.contains("-O"))
        XCTAssertThrowsError(try InspectionRequest(ip: "--script=all", ports: [80]).arguments())
        XCTAssertThrowsError(try InspectionRequest(ip: "192.0.2.0/24", ports: [80]).arguments())
        XCTAssertThrowsError(try InspectionRequest(ip: "192.0.2.1", ports: [9100]).arguments())
    }
    func testNmapXMLPreservesEvidenceAndDoesNotPromotePortGuess() throws {
        let xml = """
        <nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports>
        <port protocol="tcp" portid="443"><state state="open"/><service name="http" product="Synology DSM" version="7" tunnel="ssl" devicetype="storage-misc" ostype="Linux" hostname="diskstation" method="probed" conf="10"><cpe>cpe:/a:synology:dsm:7</cpe></service></port>
        <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh" method="table" conf="3"/></port>
        </ports></host><runstats><finished exit="success"/></runstats></nmaprun>
        """
        let report = try InspectionParser.parse(Data(xml.utf8), request: InspectionRequest(ip: "192.0.2.1", ports: [22,443]))
        XCTAssertEqual(report.services.count, 2)
        let https = try XCTUnwrap(report.services.first { $0.port == 443 })
        XCTAssertEqual(https.product, "Synology DSM")
        XCTAssertEqual(https.cpes, ["cpe:/a:synology:dsm:7"])
        XCTAssertEqual(report.deviceGuess?.label, "Possible storage-misc")
        XCTAssertTrue(report.deviceGuess?.evidence.contains("443") == true)
        XCTAssertEqual(https.reportedHostname, "diskstation")
        XCTAssertThrowsError(try InspectionParser.parse(Data(xml.utf8), request: InspectionRequest(ip: "192.0.2.2", ports: [443])))
        XCTAssertThrowsError(try InspectionParser.parse(Data("<nmaprun>".utf8), request: InspectionRequest(ip: "192.0.2.1", ports: [443])))
        XCTAssertThrowsError(try InspectionParser.parse(Data("<!DOCTYPE nmaprun [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><nmaprun>&test;</nmaprun>".utf8), request: InspectionRequest(ip: "192.0.2.1", ports: [443])))
    }
    func testTableOnlyServiceDoesNotClaimDetectedDevice() throws {
        let xml = "<nmaprun><host><address addr=\"192.0.2.1\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\" devicetype=\"router\" method=\"table\" conf=\"3\"/></port></ports></host><runstats><finished exit=\"success\"/></runstats></nmaprun>"
        let report = try InspectionParser.parse(Data(xml.utf8), request: InspectionRequest(ip: "192.0.2.1", ports: [80]))
        XCTAssertNil(report.deviceGuess)
    }
}
