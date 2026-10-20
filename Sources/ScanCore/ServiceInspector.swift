import Foundation
import Darwin

public final class ServiceInspector: @unchecked Sendable {
    public static var binary: URL? {
        ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"].first {
            FileManager.default.isExecutableFile(atPath: $0)
        }.map { URL(fileURLWithPath: $0) }
    }
    private let lock = NSLock()
    private var child: Process?
    private var cancelled = false
    public init() {}
    public func cancel() {
        lock.lock(); defer { lock.unlock() }
        cancelled = true
        if let child, child.isRunning { child.terminate() }
    }
    public func inspect(_ request: InspectionRequest, completion: @escaping (Result<HostInspection, Error>) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            let result = Result { try self.run(request) }
            DispatchQueue.main.async { completion(result) }
        }
    }
    // Internal entry point also allows integration tests against a local fixture.
    func run(_ request: InspectionRequest, executable: URL? = ServiceInspector.binary, deadline: TimeInterval = 55) throws -> HostInspection {
        let arguments = try request.arguments()
        guard let executable else { throw ScanError("Detailed checks require Nmap. Install it with: brew install nmap") }
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = ["PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/private/tmp")
        process.standardInput = FileHandle.nullDevice
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout; process.standardError = stderr
        lock.lock()
        if cancelled { lock.unlock(); throw ScanError("Device check cancelled.") }
        do { try process.run(); child = process; lock.unlock() }
        catch { lock.unlock(); throw error }
        defer { lock.lock(); child = nil; lock.unlock() }
        let output = Capture(limit: 2_097_152), errors = Capture(limit: 65536)
        let group = DispatchGroup()
        for (pipe, capture) in [(stdout, output), (stderr, errors)] {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { group.leave() }
                while true {
                    let bytes = pipe.fileHandleForReading.availableData
                    if bytes.isEmpty { break }
                    capture.append(bytes)
                }
            }
        }
        let end = ProcessInfo.processInfo.systemUptime + deadline
        var terminatedAt: TimeInterval?
        while process.isRunning {
            lock.lock(); let wasCancelled = cancelled; lock.unlock()
            let now = ProcessInfo.processInfo.systemUptime
            if wasCancelled || now >= end || output.overflowed {
                if terminatedAt == nil { terminatedAt = now; if process.isRunning { process.terminate() } }
                if let terminatedAt, now - terminatedAt > 2, process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        process.waitUntilExit()
        group.wait()
        lock.lock(); let wasCancelled = cancelled; lock.unlock()
        if wasCancelled { throw ScanError("Device check cancelled.") }
        if output.overflowed { throw ScanError("Device response exceeded the size limit.") }
        if terminatedAt != nil { throw ScanError("Device check timed out. Try again when the host responds.") }
        guard process.terminationStatus == 0 else {
            let message = String(decoding: errors.data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw ScanError(message.isEmpty ? "Nmap exited with code \(process.terminationStatus)." : String(message.prefix(1500)))
        }
        return try InspectionParser.parse(output.data, request: request)
    }
}
private final class Capture: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private var overflow = false
    private let limit: Int
    init(limit: Int) { self.limit = limit }
    func append(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        let remaining = limit - bytes.count
        bytes.append(data.prefix(remaining))
        if data.count > remaining { overflow = true }
    }
    var data: Data { lock.lock(); defer { lock.unlock() }; return bytes }
    var overflowed: Bool { lock.lock(); defer { lock.unlock() }; return overflow }
}
