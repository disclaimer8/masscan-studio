import XCTest
@testable import ScanCore

final class HostIdentityTests: XCTestCase {
    func testSystemResolverHasBoundedDeadline() {
        let start = ProcessInfo.processInfo.systemUptime
        _ = ReverseDNS.lookup("192.0.2.254", timeout: 0.15)
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 2)
        XCTAssertNil(ReverseDNS.lookup("--invalid"))
    }
    func testPrinterHintHasEvidenceAndIsNotConfirmedIdentification() {
        let guess = DeviceHints.infer(hostname: nil, ports: [80, 631, 9100])
        XCTAssertEqual(guess?.label, "Possible printer")
        XCTAssertTrue(guess?.evidence.contains("631") == true)
        XCTAssertTrue(guess?.evidence.contains("9100") == true)
    }
    func testGenericWebAndSSHDoNotIdentifyADevice() {
        XCTAssertNil(DeviceHints.infer(hostname: nil, ports: [22, 80, 443]))
        XCTAssertNil(DeviceHints.infer(hostname: "host-192-0-2-4.example", ports: [443]))
    }
    func testHostnameEvidenceIsNotMistakenForVerifiedModel() {
        let guess = DeviceHints.infer(hostname: "Denys-MacBook-Pro.local", ports: [22])
        XCTAssertEqual(guess?.label, "Possible Mac")
        XCTAssertTrue(guess?.evidence.contains("hostname") == true)
        XCTAssertEqual(DeviceHints.infer(hostname: nil, ports: [3389])?.label, "RDP host")
        XCTAssertNil(DeviceHints.infer(hostname: "notamacbookserver.example", ports: [80]))
    }
    func testReverseQueryUsesStrictIPv4() {
        XCTAssertEqual(DNSName.reverseQuery("192.168.1.23"), "23.1.168.192.in-addr.arpa.")
        XCTAssertNil(DNSName.reverseQuery("example.com"))
        XCTAssertNil(DNSName.reverseQuery("192.168.1.999"))
    }
    func testPTRWireNameAndMalformedInput() {
        XCTAssertEqual(DNSName.decodePTR([7] + Array("printer".utf8) + [5] + Array("local".utf8) + [0]), "printer.local")
        for malformed: [UInt8] in [[0], [4, 65], [192, 0], [1, 65], [1, 65, 0, 88], [1, 10, 0]] {
            XCTAssertNil(DNSName.decodePTR(malformed))
        }
    }
}
