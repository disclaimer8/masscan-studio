import Foundation
import Network

@MainActor
public final class ScanTransport {
    private var listener: NWListener?
    private var connection: NWConnection?
    private var launcher: Process?
    private var authenticated = false
    private var finished = false
    private var launched = false
    private let token = UUID().uuidString.replacingOccurrences(of: "-", with: "") +
                        UUID().uuidString.replacingOccurrences(of: "-", with: "")
    private var frames = LineFramer()
    private var timeout: Task<Void, Never>?
    public var onEvent: ((WireEvent) -> Void)?
    public init() {}

    public func start(_ config: ScanConfiguration, helper: URL, validate: Bool) throws {
        _ = try config.arguments()
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw ScanError("The scan helper is missing. Rebuild the application.")
        }
        let payload = try JSONEncoder().encode(config).base64EncodedString()
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener
        listener.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self, !self.finished else { return }
                switch state {
                case .ready:
                    guard !self.launched, let port = listener.port else { return }
                    self.launched = true
                    do { try self.launch(helper, args: [String(port.rawValue), self.token, payload, validate ? "validate" : "scan"], validate: validate) }
                    catch { self.fail(error.localizedDescription) }
                case .failed(let error): self.fail(error.localizedDescription)
                default: break
                }
            }
        }
        listener.newConnectionHandler = { [weak self] candidate in
            Task { @MainActor in
                guard let self, self.connection == nil, !self.finished else { candidate.cancel(); return }
                self.connection = candidate
                candidate.start(queue: .main)
                self.receive(candidate)
            }
        }
        listener.start(queue: .main)
        timeout = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 180_000_000_000)
            guard !Task.isCancelled, let self, !self.authenticated, !self.finished else { return }
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
            process.arguments = ["-e", "do shell script \(appleScriptQuote(command)) with administrator privileges"]
        }
        let errorPipe = Pipe()
        process.standardError = errorPipe
        process.standardOutput = FileHandle.nullDevice
        process.terminationHandler = { [weak self] process in
            let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
            Task { @MainActor in
                // Let already queued socket events drain before diagnosing a missing exit.
                try? await Task.sleep(nanoseconds: 400_000_000)
                guard let self, !self.finished else { return }
                let message = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                self.fail(message.isEmpty ? "Runner ended without a result (exit \(process.terminationStatus))." : message)
            }
        }
        launcher = process
        try process.run()
    }
    private func receive(_ candidate: NWConnection) {
        candidate.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, ended, error in
            Task { @MainActor in
                guard let self, !self.finished else { return }
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
                            self.timeout?.cancel()
                            candidate.send(content: Data("go\n".utf8), completion: .contentProcessed { _ in })
                        } else {
                            if event.kind == "exit" {
                                self.finished = true
                                self.onEvent?(event)
                                self.close()
                                return
                            }
                            self.onEvent?(event)
                        }
                    }
                }
                if ended || error != nil { self.fail("Connection to scan runner was lost."); return }
                self.receive(candidate)
            }
        }
    }
    public func stop() {
        if authenticated {
            connection?.send(content: Data("stop\n".utf8), completion: .contentProcessed { _ in })
        } else {
            fail("Scan cancelled before authorization.")
        }
    }
    public func close() {
        timeout?.cancel()
        connection?.cancel()
        listener?.cancel()
        if !authenticated, let launcher, launcher.isRunning { launcher.terminate() }
        connection = nil; listener = nil
    }
    private func fail(_ message: String) {
        guard !finished else { return }
        finished = true
        onEvent?(WireEvent("error", text: message))
        onEvent?(WireEvent("exit", text: "failed", code: -1))
        close()
    }
}
