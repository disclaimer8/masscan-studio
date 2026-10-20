import Foundation
import Network

public struct RunnerCommand: Codable {
    public var kind: String
    public var config: ScanConfiguration?
    public init(_ kind: String, config: ScanConfiguration? = nil) { self.kind = kind; self.config = config }
    public var line: Data {
        var data = (try? JSONEncoder().encode(self)) ?? Data()
        data.append(10)
        return data
    }
}

/// A connection represents one authorization, not one scan. Closing it revokes the session.
@MainActor
public final class ScanTransport {
    private var listener: NWListener?
    private var connection: NWConnection?
    private var launcher: Process?
    private var authenticated = false
    private var closed = false
    private var launched = false
    private var validatingSession: Bool?
    private var pending: ScanConfiguration?
    private var busy = false
    private let token = UUID().uuidString.replacingOccurrences(of: "-", with: "") +
                        UUID().uuidString.replacingOccurrences(of: "-", with: "")
    private var frames = LineFramer()
    private var timeout: Task<Void, Never>?
    public private(set) var isReady = false
    public private(set) var sessionPID: Int32?
    public var onEvent: ((WireEvent) -> Void)?
    public init() {}

    public func start(_ config: ScanConfiguration, helper: URL, validate: Bool) throws {
        _ = try config.arguments()
        guard !closed else { throw ScanError("The authorization session is closed.") }
        guard !busy else { throw ScanError("A scan is already running.") }
        if let validatingSession, validatingSession != validate { throw ScanError("Runner session mode cannot change.") }
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw ScanError("The scan helper is missing. Rebuild the application.")
        }
        busy = true
        if isReady {
            send(RunnerCommand("run", config: config))
            return
        }
        pending = config
        validatingSession = validate
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener
        listener.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self, !self.closed else { return }
                switch state {
                case .ready:
                    guard !self.launched, let port = listener.port else { return }
                    self.launched = true
                    do { try self.launch(helper, args: [String(port.rawValue), self.token, validate ? "validate-session" : "scan-session"], validate: validate) }
                    catch { self.fail(error.localizedDescription) }
                case .failed(let error): self.fail(error.localizedDescription)
                default: break
                }
            }
        }
        listener.newConnectionHandler = { [weak self] candidate in
            Task { @MainActor in
                guard let self, self.connection == nil, !self.closed else { candidate.cancel(); return }
                self.connection = candidate
                candidate.start(queue: .main)
                self.receive(candidate)
            }
        }
        listener.start(queue: .main)
        timeout = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 180_000_000_000)
            guard !Task.isCancelled, let self, !self.isReady, !self.closed else { return }
            self.fail("Authorization timed out. Try starting the scan again.")
        }
    }
    private func launch(_ helper: URL, args: [String], validate: Bool) throws {
        let process = Process()
        if validate {
            process.executableURL = helper
            process.arguments = args
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            let command = ([helper.path] + args).map(shellQuote).joined(separator: " ")
            process.arguments = ["-e", "with timeout of 31536000 seconds\n do shell script \(appleScriptQuote(command)) with administrator privileges\nend timeout"]
        }
        let errorPipe = Pipe()
        process.standardError = errorPipe
        process.standardOutput = FileHandle.nullDevice
        process.terminationHandler = { [weak self] process in
            let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 400_000_000)
                guard let self, !self.closed else { return }
                let message = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                self.fail(message.isEmpty ? "Runner session ended (exit \(process.terminationStatus))." : message)
            }
        }
        launcher = process
        try process.run()
    }
    private func receive(_ candidate: NWConnection) {
        candidate.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, ended, error in
            Task { @MainActor in
                guard let self, !self.closed else { return }
                if let data {
                    for line in self.frames.append(data) {
                        guard let event = try? JSONDecoder().decode(WireEvent.self, from: Data(line.utf8)) else {
                            self.fail("Invalid response from scan runner."); return
                        }
                        if !self.authenticated {
                            guard event.kind == "hello", event.text == self.token else {
                                candidate.cancel()
                                self.connection = nil
                                self.frames = LineFramer()
                                return
                            }
                            self.authenticated = true
                            candidate.send(content: Data("go\n".utf8), completion: .contentProcessed { _ in })
                        } else if event.kind == "ready" {
                            self.isReady = true
                            self.sessionPID = event.code
                            self.timeout?.cancel()
                            self.onEvent?(event)
                            if let config = self.pending {
                                self.pending = nil
                                self.send(RunnerCommand("run", config: config))
                            }
                        } else {
                            if event.kind == "exit" { self.busy = false }
                            self.onEvent?(event)
                        }
                        if self.closed { return }
                    }
                }
                if ended || error != nil { self.fail("Connection to scan runner was lost."); return }
                self.receive(candidate)
            }
        }
    }
    private func send(_ command: RunnerCommand) {
        connection?.send(content: command.line, completion: .contentProcessed { [weak self] error in
            guard let error else { return }
            Task { @MainActor in self?.fail(error.localizedDescription) }
        })
    }
    public func stop() {
        if authenticated && isReady { send(RunnerCommand("stop")) }
        else { fail("Scan cancelled before authorization.") }
    }
    public func close() {
        guard !closed else { return }
        closed = true
        isReady = false
        pending = nil
        timeout?.cancel()
        // EOF is also revocation: runner stops its owned child and exits.
        connection?.cancel()
        listener?.cancel()
        if !authenticated, let launcher, launcher.isRunning { launcher.terminate() }
        connection = nil; listener = nil
        onEvent?(WireEvent("locked"))
    }
    private func fail(_ message: String) {
        guard !closed else { return }
        let wasBusy = busy
        busy = false
        // Close first so callbacks cannot submit another job to a failing session.
        close()
        onEvent?(WireEvent("error", text: message))
        if wasBusy { onEvent?(WireEvent("exit", text: "failed", code: -1)) }
        else { onEvent?(WireEvent("session-ended", text: message)) }
    }
}
