import Foundation
import Darwin
import ScanCore

/// Root-owned runner accepts only typed scan configurations, stop, and quit.
final class Channel {
    let fd: Int32
    private let lock = NSLock()
    private var buffer = Data()
    var connected = true
    init(port: UInt16) throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ScanError("Cannot create local socket.") }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else { close(fd); throw ScanError("The app is no longer listening.") }
    }
    func send(_ event: WireEvent) {
        lock.lock(); defer { lock.unlock() }
        let data = event.line
        data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < data.count {
                let n = Darwin.send(fd, bytes.baseAddress!.advanced(by: offset), data.count - offset, 0)
                if n <= 0 { shutdown(fd, SHUT_RDWR); break }
                offset += n
            }
        }
    }
    func commands(timeout: Int32) throws -> [RunnerCommand] {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let ready = poll(&descriptor, 1, timeout)
        if ready < 0 { if errno != EINTR { connected = false }; return [] }
        guard ready > 0 else { return [] }
        var bytes = [UInt8](repeating: 0, count: 16384)
        let count = recv(fd, &bytes, bytes.count, 0)
        guard count > 0 else { connected = false; return [] }
        buffer.append(contentsOf: bytes.prefix(count))
        var commands: [RunnerCommand] = []
        while let end = buffer.firstIndex(of: 10) {
            let record = buffer[..<end]
            guard record.count <= 131072 else { throw ScanError("Oversized runner command.") }
            commands.append(try JSONDecoder().decode(RunnerCommand.self, from: record))
            buffer.removeSubrange(...end)
        }
        guard buffer.count <= 131072 else { throw ScanError("Oversized runner command.") }
        return commands
    }
    func handshake(token: String) throws {
        send(WireEvent("hello", text: token))
        var bytes = Data()
        let deadline = Date().addingTimeInterval(10)
        while bytes.count < 3 {
            guard Date() < deadline else { throw ScanError("App handshake timed out.") }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, 100) > 0 else { continue }
            var chunk = [UInt8](repeating: 0, count: 3 - bytes.count)
            let n = recv(fd, &chunk, chunk.count, 0)
            guard n > 0 else { throw ScanError("App cancelled the request.") }
            bytes.append(contentsOf: chunk.prefix(n))
        }
        guard bytes == Data("go\n".utf8) else { throw ScanError("Invalid app handshake.") }
    }
    deinit { close(fd) }
}

func temporaryDirectory(in parent: String = "/private/tmp") throws -> String {
    var template = Array((parent + "/masscan-studio.XXXXXX").utf8CString)
    guard let path = mkdtemp(&template) else { throw ScanError("Cannot create working directory.") }
    return String(cString: path)
}

func scan(_ config: ScanConfiguration, binary: String, directory: String, validate: Bool, channel: Channel) throws {
    var args = try config.arguments()
    if validate { args.append("--echo") }
    let working = try temporaryDirectory(in: directory)
    defer { unlink(working + "/paused.conf"); rmdir(working) }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: binary)
    process.arguments = args
    process.currentDirectoryURL = URL(fileURLWithPath: working)
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    let output = Pipe(), errors = Pipe()
    process.standardOutput = output; process.standardError = errors
    process.standardInput = FileHandle.nullDevice
    try process.run()
    channel.send(WireEvent("started", code: process.processIdentifier))
    let group = DispatchGroup()
    for (pipe, kind) in [(output, "stdout"), (errors, "stderr")] {
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            while true {
                let bytes = pipe.fileHandleForReading.availableData
                if bytes.isEmpty { break }
                channel.send(WireEvent(kind, text: bytes.base64EncodedString()))
            }
        }
    }
    var stopTime: Date?
    var terminated = false
    while process.isRunning {
        var requestedStop = !channel.connected
        if channel.connected {
            do {
                for command in try channel.commands(timeout: 100) {
                    switch command.kind {
                    case "stop": requestedStop = true
                    case "quit": channel.connected = false; requestedStop = true
                    case "run": channel.send(WireEvent("rejected", text: "A scan is already running."))
                    default: channel.connected = false; requestedStop = true
                    }
                }
            } catch { channel.connected = false; requestedStop = true }
            if !channel.connected { requestedStop = true }
        } else { usleep(100_000) }
        if requestedStop && stopTime == nil {
            stopTime = Date()
            if process.isRunning { process.interrupt() }
        }
        if let stopTime, Date().timeIntervalSince(stopTime) > 8, !terminated, process.isRunning {
            process.terminate(); terminated = true
        }
        if let stopTime, Date().timeIntervalSince(stopTime) > 12, process.isRunning {
            kill(process.processIdentifier, SIGKILL)
        }
    }
    process.waitUntilExit()
    group.wait()
    if let text = try? String(contentsOfFile: working + "/paused.conf", encoding: .utf8),
       let index = OutputParser.checkpoint(text) { channel.send(WireEvent("checkpoint", text: String(index))) }
    channel.send(WireEvent("exit", text: stopTime == nil ? "finished" : "stopped", code: process.terminationStatus))
}

func run() throws {
    signal(SIGPIPE, SIG_IGN)
    let args = CommandLine.arguments
    guard args.count == 4, let port = UInt16(args[1]), args[2].count == 64,
          ["scan-session", "validate-session"].contains(args[3]) else { throw ScanError("Invalid runner request.") }
    let validate = args[3] == "validate-session"
    guard validate || geteuid() == 0 else { throw ScanError("Scanning requires administrator authorization.") }
    guard let source = MasscanBinary.path else { throw ScanError("Install masscan using Homebrew first.") }
    let channel = try Channel(port: port)
    try channel.handshake(token: args[2])
    let directory = try temporaryDirectory()
    let binary = directory + "/masscan"
    defer { unlink(binary); rmdir(directory) }
    // Freeze the authorized executable for the session. Never rerun a replaceable
    // Homebrew symlink with elevated rights after authorization.
    try FileManager.default.copyItem(atPath: URL(fileURLWithPath: source).resolvingSymlinksInPath().path, toPath: binary)
    guard chmod(binary, 0o700) == 0 else { throw ScanError("Cannot prepare scanner executable.") }
    channel.send(WireEvent("ready", code: getpid()))
    while channel.connected {
        for command in try channel.commands(timeout: 500) {
            switch command.kind {
            case "quit": return
            case "stop": continue
            case "run":
                do {
                    guard let config = command.config else { throw ScanError("Missing scan configuration.") }
                    try scan(config, binary: binary, directory: directory, validate: validate, channel: channel)
                } catch {
                    channel.send(WireEvent("error", text: error.localizedDescription))
                    channel.send(WireEvent("exit", text: "failed", code: -1))
                }
            default: throw ScanError("Unsupported runner command.")
            }
            if !channel.connected { return }
        }
    }
}
do { try run() }
catch { FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8)); exit(1) }
