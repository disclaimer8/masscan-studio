import XCTest
@testable import ScanCore

final class ConfigurationTests: XCTestCase {
    func testValidTargetsProduceSeparateArguments() throws {
        var c = ScanConfiguration()
        c.targets = "192.0.2.1, 198.51.100.0/24\n203.0.113.1-203.0.113.10"
        c.exclusions = "198.51.100.5"
        c.interface = "en0"
        let args = try c.arguments()
        XCTAssertTrue(args.contains("192.0.2.1"))
        XCTAssertTrue(args.contains("198.51.100.0/24"))
        XCTAssertTrue(args.contains("203.0.113.1-203.0.113.10"))
        XCTAssertTrue(args.contains("--exclude"))
        XCTAssertTrue(args.contains("en0"))
    }

    func testRejectsInvalidTargetsAndOptionInjection() {
        for target in ["", "-p22", "1.2.3.999", "1.2.3.4/33", "1.2.3.5-1.2.3.1",
                       "example.com", "127.0.0.1;touch /tmp/oops", "1.2.3.4\n--offline"] {
            var c = ScanConfiguration()
            c.targets = target
            XCTAssertThrowsError(try c.arguments(), target)
        }
    }

    func testRejectsInvalidPortsRateAndInterface() {
        for port in ["0", "65536", "80-22", "80;id", "-p22", "U:53", ""] {
            var c = ScanConfiguration()
            c.targets = "192.0.2.1"
            c.ports = port
            XCTAssertThrowsError(try c.arguments(), port)
        }
        var c = ScanConfiguration()
        c.targets = "192.0.2.1"
        c.rate = 0
        XCTAssertThrowsError(try c.arguments())
        c.rate = 100
        c.interface = "--offline"
        XCTAssertThrowsError(try c.arguments())
    }

    func testResumeRetainsSeedAndAddsIndex() throws {
        var c = ScanConfiguration()
        c.targets = "192.0.2.1"
        c.seed = 48123
        c.resumeIndex = 99
        let args = try c.arguments()
        XCTAssertEqual(Array(args.suffix(2)), ["--resume-index", "99"])
        XCTAssertTrue(args.windowsContain(["--seed", "48123"]))
    }
}

private extension Array where Element == String {
    func windowsContain(_ pair: [String]) -> Bool {
        indices.dropLast().contains { [self[$0], self[$0 + 1]] == pair }
    }
}
