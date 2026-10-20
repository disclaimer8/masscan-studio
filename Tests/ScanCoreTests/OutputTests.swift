import XCTest
@testable import ScanCore

final class OutputTests: XCTestCase {
    func testParsesLiveResultWithoutTreatingDiagnosticsAsResults() {
        let r = OutputParser.result("Discovered open port 443/tcp on 192.0.2.10     ")
        XCTAssertEqual(r?.ip, "192.0.2.10")
        XCTAssertEqual(r?.port, 443)
        XCTAssertNil(OutputParser.result("FAIL: adapter not found"))
        XCTAssertNil(OutputParser.result("Discovered open port 99999/tcp on 192.0.2.10"))
    }
    func testParsesProgressAndDrainState() {
        let p = OutputParser.progress("rate:  1.25-kpps, 42.50% done, 0:01:23 remaining, found=8")
        XCTAssertEqual(p?.percent, 42.5)
        XCTAssertEqual(p?.packetsPerSecond, 1250)
        XCTAssertEqual(p?.remaining, "0:01:23")
        XCTAssertEqual(OutputParser.progress("rate:  0.00-kpps, 100.00% done, waiting 3-secs, found=8")?.remaining, "Receiving final replies")
    }
    func testFramesSplitRecordsAndCarriageReturns() {
        var f = LineFramer()
        XCTAssertEqual(f.append(Data("one\rpar".utf8)), ["one"])
        XCTAssertEqual(f.append(Data("tial\nlast".utf8)), ["partial"])
        XCTAssertEqual(f.finish(), ["last"])
        XCTAssertEqual(f.finish(), [])
    }
    func testResumeIndexIsParsedExactly() {
        XCTAssertEqual(OutputParser.checkpoint("seed = 42\nresume-index = 18446744073709551614\n"), 18446744073709551614)
        XCTAssertNil(OutputParser.checkpoint("resume-index = -1"))
    }
    func testCSVAndIPSort() {
        let rows = [PortResult(ip: "192.0.2.10", port: 443, discoveredAt: Date(timeIntervalSince1970: 0))]
        let csv = Export.csv(rows)
        XCTAssertTrue(csv.hasPrefix("ip,port,protocol,service_hint,discovered_at\r\n"))
        XCTAssertTrue(csv.contains("192.0.2.10,443,tcp,HTTPS,1970-01-01T00:00:00Z"))
        XCTAssertLessThan(PortResult(ip: "192.0.2.2", port: 80).ipSort, rows[0].ipSort)
    }
    func testShellQuoteCannotExecuteEmbeddedCommand() throws {
        let input = "a' $(touch /tmp/masscan-studio-injection) `id`\nend"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf %s " + shellQuote(input)]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let result = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(String(decoding: result, as: UTF8.self), input)
    }
    func testRealMasscanAcceptsGeneratedArgumentsWithoutScanning() throws {
        guard let binary = MasscanBinary.path else { throw XCTSkip("masscan is not installed") }
        var c = ScanConfiguration()
        c.targets = "192.0.2.1"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: binary)
        p.arguments = try c.arguments() + ["--echo"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, String(decoding: data, as: UTF8.self))
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("192.0.2.1"))
    }
    func testAppleScriptShellBridgePreservesSpacesAndQuotes() throws {
        let input = "/Applications/Masscan Studio.app/a'b \"c\" \\ $HOME `id`"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "do shell script \(appleScriptQuote("printf %s " + shellQuote(input)))"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertEqual(String(decoding: data, as: UTF8.self).trimmingCharacters(in: .newlines), input)
    }
}
