import Darwin
import Foundation
import XCTest

/// Persistent runner checks against the real ScanHelper executable. Every job uses the
/// helper's validate-session mode (masscan --echo); nothing here scans.
final class RunnerTests: XCTestCase {
    private static let token = String(repeating: "0123456789abcdef", count: 4)

    /// ScanHelper is built next to the test bundle by `swift build` / `swift test`.
    private var helper: URL {
        Bundle(for: RunnerTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("ScanHelper")
    }

    // MARK: harness

    /// One end of a loopback TCP connection with line framing and bounded waits.
    private final class Socket {
        let fd: Int32
        private var buffer = Data()
        init(fd: Int32) {
            self.fd = fd
            var quiet: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &quiet, socklen_t(MemoryLayout<Int32>.size))
        }
        deinit { close() }
        func close() { if fdOpen { Darwin.close(fd); fdOpen = false } }
        private var fdOpen = true

        private func wait(_ events: Int16, seconds: TimeInterval) -> Bool {
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            return poll(&descriptor, 1, Int32(seconds * 1000)) > 0
        }
        func send(_ data: Data) {
            data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < data.count {
                    let n = Darwin.send(fd, bytes.baseAddress!.advanced(by: offset), data.count - offset, 0)
                    if n <= 0 { break }
                    offset += n
                }
            }
        }
        func send(_ text: String) { send(Data(text.utf8)) }
        /// Reads whatever arrives next (at most 4096 bytes). Empty on timeout or EOF.
        func receiveSome() -> Data {
            guard wait(Int16(POLLIN), seconds: 5) else { return Data() }
            var bytes = [UInt8](repeating: 0, count: 4096)
            let n = recv(fd, &bytes, bytes.count, 0)
            return n > 0 ? Data(bytes.prefix(n)) : Data()
        }
        /// One newline-terminated record, or nil on timeout or EOF.
        func readLine() -> Data? {
            while true {
                if let end = buffer.firstIndex(of: 10) {
                    let line = Data(buffer[..<end])
                    buffer.removeSubrange(...end)
                    return line
                }
                guard wait(Int16(POLLIN), seconds: 5) else { return nil }
                var bytes = [UInt8](repeating: 0, count: 16384)
                let n = recv(fd, &bytes, bytes.count, 0)
                guard n > 0 else { return nil }
                buffer.append(contentsOf: bytes.prefix(n))
            }
        }
        func readEvent() throws -> [String: Any] {
            let line = try XCTUnwrap(readLine(), "runner closed or went silent")
            return try XCTUnwrap(JSONSerialization.jsonObject(with: line) as? [String: Any])
        }
    }

    private struct HarnessError: Error {}

    private struct Session {
        let process: Process
        let client: Socket
        let stderr: Pipe

        /// Waits for the helper to exit (kills it on timeout) and returns what it wrote to stderr.
        @discardableResult
        func finish(file: StaticString = #filePath, line: UInt = #line) -> String {
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { usleep(10_000) }
            if process.isRunning {
                process.terminate()
                XCTFail("runner did not exit within 5 s", file: file, line: line)
            }
            process.waitUntilExit()
            return String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        }
    }

    private func listen() throws -> (fd: Int32, port: UInt16) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        XCTAssertEqual(bound, 0)
        XCTAssertEqual(Darwin.listen(fd, 1), 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        XCTAssertEqual(named, 0)
        return (fd, UInt16(bigEndian: address.sin_port))
    }

    /// Starts the helper against a fresh loopback listener and returns the accepted connection.
    private func launch() throws -> Session {
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: helper.path), "ScanHelper is not built at \(helper.path)")
        let (server, port) = try listen()
        defer { Darwin.close(server) }
        let process = Process(), errors = Pipe()
        process.executableURL = helper
        process.arguments = [String(port), Self.token, "validate-session"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        try process.run()
        addTeardownBlock { if process.isRunning { process.terminate() } }
        var descriptor = pollfd(fd: server, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, 5000) > 0 else {
            process.terminate()
            XCTFail("helper never connected (is masscan installed?)")
            throw HarnessError()
        }
        let accepted = accept(server, nil, nil)
        XCTAssertGreaterThanOrEqual(accepted, 0)
        return Session(process: process, client: Socket(fd: accepted), stderr: errors)
    }

    /// Reads the hello, sends "go\n" one byte at a time and returns the helper's pid from "ready".
    private func authorize(_ session: Session) throws -> Int32 {
        let hello = try session.client.readEvent()
        XCTAssertEqual(hello["kind"] as? String, "hello")
        XCTAssertEqual(hello["text"] as? String, Self.token)
        for byte in ["g", "o", "\n"] {
            session.client.send(byte)
            usleep(10_000)
        }
        let ready = try session.client.readEvent()
        XCTAssertEqual(ready["kind"] as? String, "ready")
        return Int32(truncating: try XCTUnwrap(ready["code"] as? NSNumber))
    }

    private func config(_ target: String) -> [String: Any] {
        ["targets": target, "ports": "80,443", "exclusions": "", "interface": "", "rate": 100, "seed": 42]
    }

    /// Runs one job and returns every event up to and including "exit".
    private func job(_ session: Session, target: String = "192.0.2.1") throws -> [[String: Any]] {
        let body = try JSONSerialization.data(withJSONObject: ["kind": "run", "config": config(target)] as [String: Any])
        session.client.send(body + Data([10]))
        var events: [[String: Any]] = []
        while true {
            let event = try session.client.readEvent()
            events.append(event)
            if event["kind"] as? String == "exit" { return events }
        }
    }

    // MARK: tests

    func testFragmentedHandshakeAndTwoJobsKeepSameRunner() throws {
        let session = try launch()
        let pid = try authorize(session)
        XCTAssertEqual(pid, session.process.processIdentifier)
        for target in ["192.0.2.1", "192.0.2.2"] {
            let events = try job(session, target: target)
            XCTAssertEqual((events.last?["code"] as? NSNumber)?.intValue, 0)
            var output = Data()
            for event in events where event["kind"] as? String == "stdout" {
                output.append(try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(event["text"] as? String))))
            }
            let text = String(decoding: output, as: UTF8.self)
            XCTAssertTrue(text.contains("range = \(target)"), text)
            XCTAssertTrue(text.contains("ports = 80,443"), text)
            XCTAssertTrue(session.process.isRunning)
        }
        session.client.send("{\"kind\":\"quit\"}\n")
        session.finish()
        XCTAssertEqual(session.process.terminationStatus, 0)
    }

    func testDisconnectBeforeGoNeverStartsScanner() throws {
        let session = try launch()
        XCTAssertFalse(session.client.receiveSome().isEmpty, "expected the hello")
        session.client.close()
        let stderr = session.finish()
        XCTAssertNotEqual(session.process.terminationStatus, 0)
        XCTAssertTrue(stderr.contains("App cancelled"), stderr)
    }

    func testIdleDisconnectRevokesRunner() throws {
        let session = try launch()
        _ = try authorize(session)
        session.client.close()
        session.finish()
        XCTAssertEqual(session.process.terminationStatus, 0)
    }

    func testInvalidHandshakeNeverStartsScanner() throws {
        let session = try launch()
        XCTAssertFalse(session.client.receiveSome().isEmpty, "expected the hello")
        session.client.send("bad")
        let stderr = session.finish()
        XCTAssertNotEqual(session.process.terminationStatus, 0)
        XCTAssertTrue(stderr.contains("Invalid app handshake"), stderr)
    }

    func testArgumentInjectionIsRejectedAndSessionRecovers() throws {
        let session = try launch()
        _ = try authorize(session)
        let rejected = try job(session, target: "--offline")
        XCTAssertEqual(rejected.map { $0["kind"] as? String }, ["error", "exit"])
        XCTAssertTrue((rejected[0]["text"] as? String ?? "").contains("Invalid IPv4 target"))
        XCTAssertEqual((try job(session).last?["code"] as? NSNumber)?.intValue, 0)
        session.client.send("{\"kind\":\"quit\"}\n")
        session.finish()
    }

    func testOversizedCommandClosesRunner() throws {
        let session = try launch()
        _ = try authorize(session)
        session.client.send(Data(repeating: UInt8(ascii: "x"), count: 131_073))
        let stderr = session.finish()
        XCTAssertNotEqual(session.process.terminationStatus, 0)
        XCTAssertTrue(stderr.contains("Oversized runner command"), stderr)
    }
}
