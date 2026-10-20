import Foundation
import Darwin
import ScanCore

// Never accepts a shell command, arbitrary executable, or output path.
final class Channel {
    let fd: Int32
    private let lock = NSLock()
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
                if n <= 0 { break }
                offset += n
            }
        }
    }
    deinit { close(fd) }
}

func run() throws {
    signal(SIGPIPE, SIG_IGN)
    let args = CommandLine.arguments
    guard args.count == 5, let port = UInt16(args[1]),
          args[2].count == 64, let data = Data(base64Encoded: args[3]), data.count <= 131072,
          ["scan", "validate"].contains(args[4]) else { throw ScanError("Invalid runner request.") }
    let config = try JSONDecoder().decode(ScanConfiguration.self, from: data)
    var scanArgs = try config.arguments()
    guard let executable = MasscanBinary.path else { throw ScanError("Install masscan using Homebrew first.") }
    let validate = args[4] == "validate"
    guard validate || geteuid() == 0 else { throw ScanError("Scanning requires administrator authorization.") }
    if validate { scanArgs.append("--echo") }
    let channel = try Channel(port: port)
    channel.send(WireEvent("hello", text: args[2]))
    var pollFD = pollfd(fd: channel.fd, events: Int16(POLLIN), revents: 0)
    var handshake = Data()
    let handshakeDeadline = Date().addingTimeInterval(10)
    while handshake.count < 3 {
        guard Date() < handshakeDeadline else { throw ScanError("App handshake timed out.") }
        guard poll(&pollFD, 1, 100) > 0 else { continue }
        var bytes = [UInt8](repeating: 0, count: 3 - handshake.count)
        let count = recv(channel.fd, &bytes, bytes.count, 0)
        guard count > 0 else { throw ScanError("App cancelled the request.") }
        handshake.append(contentsOf: bytes.prefix(count))
    }
    guard handshake == Data("go\n".utf8) else { throw ScanError("Invalid app handshake.") }

    // Only root-owned files in a private directory; no elevated user-path writes.
    var template = Array("/private/tmp/masscan-studio.XXXXXX".utf8CString)
    guard let temporary = mkdtemp(&template) else { throw ScanError("Cannot create working directory.") }
    let directory = String(cString: temporary)
    defer {
        unlink(directory + "/paused.conf")
        rmdir(directory)
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = scanArgs
    process.currentDirectoryURL = URL(fileURLWithPath: directory)
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    let output = Pipe(), errors = Pipe()
    process.standardOutput = output
    process.standardError = errors
    process.standardInput = FileHandle.nullDevice
    do { try process.run() }
    catch { channel.send(WireEvent("error", text: error.localizedDescription)); throw error }
    channel.send(WireEvent("started"))
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
    var control = LineFramer()
    while process.isRunning {
        pollFD.revents = 0
        let ready = poll(&pollFD, 1, 100)
        if ready > 0 {
            var bytes = [UInt8](repeating: 0, count: 1024)
            let count = recv(channel.fd, &bytes, bytes.count, 0)
            let stop = count <= 0 || control.append(Data(bytes.prefix(max(0, count)))).contains("stop")
            if stop && stopTime == nil {
                stopTime = Date()
                process.interrupt()
            }
        }
        if let stopTime, Date().timeIntervalSince(stopTime) > 8, !terminated, process.isRunning {
            process.terminate()
            terminated = true
        }
        if let stopTime, Date().timeIntervalSince(stopTime) > 12, process.isRunning {
            kill(process.processIdentifier, SIGKILL)
        }
    }
    process.waitUntilExit()
    group.wait()
    if let checkpoint = try? String(contentsOfFile: directory + "/paused.conf", encoding: .utf8),
       let index = OutputParser.checkpoint(checkpoint) {
        channel.send(WireEvent("checkpoint", text: String(index)))
    }
    channel.send(WireEvent("exit", text: stopTime == nil ? "finished" : "stopped", code: process.terminationStatus))
}
do { try run() }
catch {
    FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
    exit(1)
}
