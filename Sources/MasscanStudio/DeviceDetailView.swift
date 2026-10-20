import SwiftUI
import ScanCore

struct DeviceTarget: Identifiable {
    let sessionID: UUID
    let ip: String
    var id: String { sessionID.uuidString + "/" + ip }
}
struct DeviceDetailView: View {
    @EnvironmentObject private var store: SessionStore
    @Environment(\.dismiss) private var dismiss
    let target: DeviceTarget
    private var rows: [PortResult] {
        store.sessions.first { $0.id == target.sessionID }?.results.filter { $0.ip == target.ip } ?? []
    }
    private var report: HostInspection? { rows.compactMap(\.inspection).first }
    private var hostname: String? { rows.compactMap(\.hostname).first }
    private var running: Bool { store.inspectingHost == target.id }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(hostname ?? target.ip).font(.title2.bold()).textSelection(.enabled)
                    Text(hostname == nil ? "Device details" : target.ip).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
                if let row = rows.first, let url = WebsiteLink.url(for: row, hostRows: rows) {
                    Link(destination: url) { Label("Open Website", systemImage: "arrow.up.right.square") }.help(url.absoluteString)
                }
            }.padding(24)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Probe the discovered TCP ports on this host to identify services, software versions and possible device or OS details.")
                        .foregroundStyle(.secondary)
                    LabeledContent("Ports", value: Array(Set(rows.map(\.port))).sorted().map(String.init).joined(separator: ", "))
                    Text("One host · light service detection · up to 55 seconds · no administrator password")
                        .font(.caption).foregroundStyle(.secondary)
                    if rows.contains(where: { $0.port == 9100 }) {
                        Text("Raw printing port 9100 is excluded from probes.").font(.caption).foregroundStyle(.secondary)
                    }
                    if ServiceInspector.binary == nil {
                        Text("Install Nmap to enable detailed checks: brew install nmap").textSelection(.enabled)
                    }
                    if running {
                        HStack { ProgressView().controlSize(.small); Text("Checking service responses…") }
                    }
                    if let error = store.inspectionErrors[target.id] {
                        Text(error).foregroundStyle(.orange).textSelection(.enabled)
                    }
                    if let report {
                        Divider()
                        HStack {
                            Text("Last check").font(.headline)
                            Spacer()
                            Text(report.date, format: .dateTime.day().month().hour().minute()).font(.caption).foregroundStyle(.secondary)
                        }
                        if let guess = report.deviceGuess {
                            Text(guess.label).font(.headline)
                            Text(guess.evidence).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                        } else {
                            Text("The responses did not identify a device type. Service details are shown below.").foregroundStyle(.secondary)
                        }
                        ForEach(report.services) { service in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text("TCP \(String(service.port))").font(.system(.headline, design: .monospaced))
                                    Text(service.name).fontWeight(.medium)
                                    Spacer()
                                    Text(service.state).foregroundStyle(service.state == "open" ? .green : .secondary)
                                }
                                if !service.summary.isEmpty { Text(service.summary).textSelection(.enabled) }
                                if !service.deviceType.isEmpty { detail("Device type hint", service.deviceType) }
                                if !service.osType.isEmpty { detail("OS hint from service", service.osType) }
                                if !service.reportedHostname.isEmpty { detail("Name reported by service", service.reportedHostname) }
                                if !service.tunnel.isEmpty { detail("Transport", service.tunnel.uppercased()) }
                                ForEach(service.cpes, id: \.self) { detail("CPE", $0) }
                                Text(service.method == "probed" ?
                                     "Source: matched service response. Nmap service confidence: \(service.confidence)/10; this is not device certainty." :
                                     "Source: port table / no confirmed service response.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                                .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
                        }
                        if report.services.isEmpty { Text("No per-port details returned. The host may no longer be reachable.").foregroundStyle(.secondary) }
                    } else if !running {
                        Text(rows.first?.deviceEvidence ?? "No detailed check yet. Open ports alone do not establish a device model.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }.padding(24)
            }
            Divider()
            HStack {
                if running { Button("Cancel Check") { store.cancelInspection() } }
                else {
                    Button(report == nil ? "Inspect Device" : "Check Again") {
                        store.inspectDevice(sessionID: target.sessionID, ip: target.ip)
                    }.buttonStyle(.borderedProminent)
                        .disabled(store.inspectingHost != nil || ServiceInspector.binary == nil || rows.isEmpty)
                    if store.inspectingHost != nil { Text("Another device check is running.").font(.caption).foregroundStyle(.secondary) }
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }.padding(20)
        }.frame(width: 720, height: 650)
    }
    private func detail(_ label: String, _ value: String) -> some View {
        LabeledContent(label) { Text(value).textSelection(.enabled) }.font(.callout)
    }
}
