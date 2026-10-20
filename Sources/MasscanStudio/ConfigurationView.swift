import SwiftUI
import ScanCore

struct ConfigurationView: View {
    @EnvironmentObject var store: SessionStore
    @Environment(\.dismiss) private var dismiss
    @State var config: ScanConfiguration
    @State var name: String
    @State private var saveProfile = false
    @State private var showCommand = false
    @State private var localError: String?
    private var validationError: String? {
        do { _ = try config.arguments(); return nil } catch { return error.localizedDescription }
    }
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("New scan").font(.title2.weight(.semibold))
                    Text("Choose a scope, then let masscan do the work.").foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "dot.radiowaves.left.and.right").font(.title).foregroundStyle(.teal)
            }.padding(24)
            Divider()
            ScrollView {
                Form {
                    Section("SCOPE") {
                        TextField("Name", text: $name, prompt: Text("Optional scan name"))
                        TextField("Targets", text: $config.targets, prompt: Text("192.168.1.0/24"), axis: .vertical)
                            .lineLimit(2...4).font(.system(.body, design: .monospaced))
                        Text("IPv4 addresses, CIDRs or ranges. Separate with commas or newlines.")
                            .font(.caption).foregroundStyle(.secondary)
                        TextField("TCP ports", text: $config.ports, prompt: Text("22,80,443 or 1-1024"))
                            .font(.system(.body, design: .monospaced))
                        HStack {
                            Text("Presets").foregroundStyle(.secondary)
                            Spacer()
                            Button("Web") { config.ports = "80,443,8080,8443" }
                            Button("Common") { config.ports = "21,22,25,53,80,110,143,443,445,3389,8080" }
                            Button("All TCP") { config.ports = "1-65535" }
                        }.controlSize(.small)
                    }
                    Section("SCAN SETTINGS") {
                        TextField("Packets / second", value: $config.rate, format: .number.grouping(.never))
                        TextField("Interface", text: $config.interface, prompt: Text("Automatic, or en0"))
                        TextField("Excluded targets", text: $config.exclusions, prompt: Text("Optional IPv4 addresses or ranges"), axis: .vertical)
                            .lineLimit(1...3)
                        Text("Start at 100 packets/s. Administrator authorization is requested once per app session.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Section {
                        Toggle("Look up hostnames", isOn: Binding(
                            get: { config.resolveHostnames != false },
                            set: { config.resolveHostnames = $0 }))
                        Text("Uses system DNS / mDNS in the background, up to 512 hosts per scan. Device hints are estimates based on names and ports.")
                            .font(.caption).foregroundStyle(.secondary)
                        Toggle("Save as a reusable profile", isOn: $saveProfile)
                        DisclosureGroup("Command preview", isExpanded: $showCommand) {
                            Text(config.preview).font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
                        }
                    }
                }.formStyle(.grouped).disabled(store.validating)
                if !store.validationOutput.isEmpty {
                    ScrollView {
                        Text(store.validationOutput).font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    }.frame(maxHeight: 130).background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
                        .padding(.horizontal, 24).padding(.bottom, 12)
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                if let message = localError ?? (config.targets.isEmpty ? nil : validationError) {
                    Text(message).font(.caption).foregroundStyle(.orange)
                }
                HStack {
                    Button(store.validating ? "Validating…" : "Validate Setup") { store.validate(config) }
                        .disabled(validationError != nil || store.validating || !store.installed)
                        .help("Check the generated configuration without sending packets.")
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Start Scan") {
                        if let validationError { localError = validationError; return }
                        if saveProfile { store.saveProfile(name: name, config: config) }
                        store.start(name: name, config: config)
                        dismiss()
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                        .disabled(validationError != nil || store.busy || !store.installed || store.validating)
                }
            }.padding(20)
        }.frame(width: 650, height: 710)
            .onAppear { store.validationOutput = "" }
            .onChange(of: config) { _, _ in store.validationOutput = "" }
    }
}
