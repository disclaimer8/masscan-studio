import XCTest
@testable import ScanCore

final class TransportTests: XCTestCase {
    @MainActor
    func testRealHelperStreamsValidationAndTerminates() async throws {
        guard MasscanBinary.path != nil else { throw XCTSkip("masscan not installed") }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let helper = root.appendingPathComponent(".build/debug/ScanHelper")
        let transport = ScanTransport()
        let complete = expectation(description: "runner completed")
        var output = ""
        var events: [String] = []
        var exitCode: Int32?
        transport.onEvent = { event in
            events.append(event.kind)
            if event.kind == "stdout", let text = event.text, let data = Data(base64Encoded: text) {
                output += String(decoding: data, as: UTF8.self)
            }
            if event.kind == "exit" { exitCode = event.code; complete.fulfill() }
        }
        var config = ScanConfiguration()
        config.targets = "192.0.2.1"
        try transport.start(config, helper: helper, validate: true)
        await fulfillment(of: [complete], timeout: 15)
        XCTAssertTrue(events.contains("started"))
        XCTAssertFalse(events.contains("error"))
        XCTAssertEqual(exitCode, 0)
        XCTAssertTrue(output.contains("192.0.2.1"))
        transport.close()
    }
    @MainActor
    func testInvalidConfigNeverStartsHelper() throws {
        let transport = ScanTransport()
        var config = ScanConfiguration()
        config.targets = "--offline"
        XCTAssertThrowsError(try transport.start(config, helper: URL(fileURLWithPath: "/usr/bin/false"), validate: true))
    }
    @MainActor
    func testCancelBeforeAuthorizationIsTerminal() {
        let transport = ScanTransport()
        var events: [WireEvent] = []
        transport.onEvent = { events.append($0) }
        transport.stop()
        transport.stop()
        XCTAssertEqual(events.filter { $0.kind == "exit" }.count, 1)
        XCTAssertEqual(events.last?.code, -1)
    }
}
