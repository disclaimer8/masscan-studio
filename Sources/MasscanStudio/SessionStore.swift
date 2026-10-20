import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ScanCore

struct ScanSession: Codable, Identifiable {
    var id = UUID()
    var name: String
    var date = Date()
    var config: ScanConfiguration
    var status = "Ready"
    var results: [PortResult] = []
    var log = ""
    var percent: Double = 0
}
struct ScanProfile: Codable, Identifiable {
    var id = UUID()
    var name: String
    var config: ScanConfiguration
}

@MainActor
final class SessionStore: ObservableObject {
    @Published var sessions: [ScanSession] = []
    @Published var profiles: [ScanProfile] = []
    @Published var selection: UUID?
    @Published var activeID: UUID?
    @Published var error: String?
    @Published var rate: Double = 0
    @Published var remaining = ""
    @Published var validationOutput = ""
    @Published var validating = false
    private var transport: ScanTransport?
    private var validationTransport: ScanTransport?
    private var stdout = LineFramer()
    private var stderr = LineFramer()
    private var ids = Set<String>()
    private var saveTask: Task<Void, Never>?
    private let directory: URL
    var selected: ScanSession? { sessions.first { $0.id == selection } }
    var helperURL: URL { Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("ScanHelper") }
    var installed: Bool { MasscanBinary.path != nil }
    var busy: Bool { activeID != nil }

    init() {
        directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Masscan Studio")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: directory.appendingPathComponent("sessions.json").path) {
                sessions = try JSONDecoder().decode([ScanSession].self, from: Data(contentsOf: directory.appendingPathComponent("sessions.json")))
            }
            if FileManager.default.fileExists(atPath: directory.appendingPathComponent("profiles.json").path) {
                profiles = try JSONDecoder().decode([ScanProfile].self, from: Data(contentsOf: directory.appendingPathComponent("profiles.json")))
            }
            for i in sessions.indices where ["Scanning", "Authorizing", "Stopping"].contains(sessions[i].status) {
                sessions[i].status = "Interrupted"
            }
            selection = sessions.first?.id
        } catch { self.error = "Could not load local history: \(error.localizedDescription)" }
    }
    func start(name: String, config: ScanConfiguration, resume: UUID? = nil) {
        guard !busy else { return }
        do {
            _ = try config.arguments()
            guard installed else { throw ScanError("Install masscan first: brew install masscan") }
            let id: UUID
            if let resume, let index = sessions.firstIndex(where: { $0.id == resume }) {
                id = resume
                sessions[index].status = "Authorizing"
                sessions[index].log += "\nResuming scan…\n"
            } else {
                let session = ScanSession(name: name.trimmingCharacters(in: .whitespaces).isEmpty ? config.targets : name, config: config, status: "Authorizing")
                sessions.insert(session, at: 0)
                id = session.id
            }
            activeID = id; selection = id
            ids = Set(sessions.first { $0.id == id }!.results.map(\.id))
            stdout = LineFramer(); stderr = LineFramer()
            rate = 0; remaining = "Waiting for authorization"
            let transport = ScanTransport()
            self.transport = transport
            transport.onEvent = { [weak self] event in self?.handle(event, id: id) }
            try transport.start(config, helper: helperURL, validate: false)
            save()
        } catch {
            if let activeID, let index = sessions.firstIndex(where: { $0.id == activeID }) {
                sessions[index].status = "Failed"
            }
            activeID = nil
            self.error = error.localizedDescription
            save()
        }
    }
    func stop() {
        guard let id = activeID, let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[index].status = "Stopping"
        remaining = "Receiving final replies"
        transport?.stop()
    }
    func resumeSelected() {
        guard let session = selected, session.config.resumeIndex != nil else { return }
        start(name: session.name, config: session.config, resume: session.id)
    }
    private func handle(_ event: WireEvent, id: UUID) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        switch event.kind {
        case "started":
            sessions[index].status = "Scanning"
            // The previous checkpoint is consumed; a new one must arrive to allow resume.
            sessions[index].config.resumeIndex = nil
            remaining = "Starting"
        case "stdout", "stderr":
            guard let text = event.text, let data = Data(base64Encoded: text) else { return }
            let lines = event.kind == "stdout" ? stdout.append(data) : stderr.append(data)
            ingest(lines, index: index)
        case "checkpoint":
            sessions[index].config.resumeIndex = event.text.flatMap(UInt64.init)
        case "error":
            sessions[index].log += (event.text ?? "Unknown error") + "\n"
            error = event.text
        case "exit":
            ingest(stdout.finish() + stderr.finish(), index: index)
            if event.text == "failed" || event.code != 0 {
                sessions[index].status = "Failed"
                if error == nil { error = "masscan exited with code \(event.code ?? -1). See the scan log." }
            } else if sessions[index].config.resumeIndex != nil {
                sessions[index].status = "Paused"
            } else if event.text == "stopped" {
                sessions[index].status = "Stopped"
            } else {
                sessions[index].status = "Completed"
                sessions[index].percent = 100
            }
            activeID = nil
            transport = nil
            remaining = ""
            save()
        default: break
        }
        scheduleSave()
    }
    private func ingest(_ lines: [String], index: Int) {
        var additions: [PortResult] = []
        for line in lines {
            if let result = OutputParser.result(line) {
                if ids.insert(result.id).inserted { additions.append(result) }
            } else if let progress = OutputParser.progress(line) {
                sessions[index].percent = progress.percent
                rate = progress.packetsPerSecond
                remaining = progress.remaining
            } else {
                sessions[index].log += line + "\n"
            }
        }
        sessions[index].results.append(contentsOf: additions)
        if sessions[index].log.count > 60_000 { sessions[index].log = String(sessions[index].log.suffix(60_000)) }
    }
    func validate(_ config: ScanConfiguration) {
        guard !validating else { return }
        do {
            _ = try config.arguments()
            validating = true; validationOutput = ""
            let transport = ScanTransport()
            validationTransport = transport
            transport.onEvent = { [weak self] event in
                guard let self else { return }
                if ["stdout", "stderr"].contains(event.kind), let text = event.text, let data = Data(base64Encoded: text) {
                    self.validationOutput += String(decoding: data, as: UTF8.self)
                }
                if event.kind == "error" { self.validationOutput += event.text ?? "" }
                if event.kind == "exit" {
                    self.validating = false
                    self.validationTransport = nil
                    self.validationOutput = (event.code == 0 ? "Configuration accepted. No packets sent.\n\n" : "Validation failed.\n\n") + self.validationOutput
                }
            }
            try transport.start(config, helper: helperURL, validate: true)
        } catch { validating = false; validationOutput = error.localizedDescription }
    }
    func saveProfile(name: String, config: ScanConfiguration) {
        do {
            _ = try config.arguments()
            profiles.append(ScanProfile(name: name.isEmpty ? config.targets : name, config: config))
            save()
        } catch { self.error = error.localizedDescription }
    }
    func deleteSession(_ id: UUID) {
        guard id != activeID else { return }
        sessions.removeAll { $0.id == id }
        if selection == id { selection = sessions.first?.id }
        save()
    }
    func deleteProfile(_ id: UUID) { profiles.removeAll { $0.id == id }; save() }
    private func scheduleSave() {
        guard saveTask == nil else { return }
        saveTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            guard !Task.isCancelled else { return }
            self?.save()
            self?.saveTask = nil
        }
    }
    func save() {
        do {
            let encoder = JSONEncoder()
            try encoder.encode(sessions).write(to: directory.appendingPathComponent("sessions.json"), options: .atomic)
            try encoder.encode(profiles).write(to: directory.appendingPathComponent("profiles.json"), options: .atomic)
        } catch { self.error = "Could not save history: \(error.localizedDescription)" }
    }
    func export(json: Bool, rows: [PortResult]) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [json ? .json : .commaSeparatedText]
        panel.nameFieldStringValue = "masscan-results.\(json ? "json" : "csv")"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                encoder.dateEncodingStrategy = .iso8601
                try encoder.encode(rows).write(to: url, options: .atomic)
            } else { try Export.csv(rows).write(to: url, atomically: true, encoding: .utf8) }
        } catch { self.error = "Export failed: \(error.localizedDescription)" }
    }
    func shutdown() {
        transport?.stop()
        transport?.close()
        validationTransport?.close()
        save()
    }
}
