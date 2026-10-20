import SwiftUI
import AppKit
import ScanCore

struct ContentView: View {
    @EnvironmentObject var store: SessionStore
    @State private var sheet = false
    @State private var draft = ScanConfiguration()
    @State private var draftName = ""
    @State private var search = ""
    @State private var showLog = false
    @State private var sortOrder = [KeyPathComparator(\PortResult.ipSort), KeyPathComparator(\PortResult.port)]
    @State private var selectedRows = Set<PortResult.ID>()

    private var rows: [PortResult] {
        (store.selected?.results ?? []).filter {
            search.isEmpty || "\($0.ip) \($0.port) \($0.proto) \($0.service)"
                .localizedCaseInsensitiveContains(search)
        }.sorted(using: sortOrder)
    }
    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "dot.radiowaves.left.and.right")
                        .font(.system(size: 25, weight: .medium)).foregroundStyle(.teal)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("MASSCAN").font(.system(size: 14, weight: .bold, design: .rounded)).tracking(2)
                        Text("STUDIO").font(.system(size: 10, weight: .medium)).tracking(3).foregroundStyle(.secondary)
                    }
                    Spacer()
                }.padding(20)
                List(selection: $store.selection) {
                    Section("PROFILES") {
                        if store.profiles.isEmpty {
                            Text("Save a scan setup to reuse it.").font(.caption).foregroundStyle(.secondary)
                                .padding(.vertical, 5)
                        }
                        ForEach(store.profiles) { profile in
                            Button {
                                draft = profile.config; draft.resumeIndex = nil
                                draft.seed = UInt64.random(in: 1...UInt64(UInt32.max))
                                draftName = profile.name; sheet = true
                            } label: {
                                Label(profile.name, systemImage: "slider.horizontal.3").lineLimit(1)
                            }.buttonStyle(.plain).disabled(store.busy)
                                .contextMenu { Button("Delete Profile", role: .destructive) { store.deleteProfile(profile.id) } }
                        }
                    }
                    Section("SCAN HISTORY") {
                        if store.sessions.isEmpty {
                            Text("Your scans will appear here.").font(.caption).foregroundStyle(.secondary).padding(.vertical, 5)
                        }
                        ForEach(store.sessions) { session in
                            HStack(alignment: .top, spacing: 10) {
                                Circle().fill(statusColor(session.status)).frame(width: 7, height: 7).padding(.top, 5)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(session.name).fontWeight(.medium).lineLimit(1)
                                    Text("\(session.results.count) ports · \(session.status)")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Text(session.date, format: .dateTime.month(.abbreviated).day().hour().minute())
                                        .font(.caption2).foregroundStyle(.tertiary)
                                }
                            }.padding(.vertical, 5).tag(session.id)
                                .contextMenu {
                                    Button("Use Settings for New Scan") {
                                        draft = session.config; draft.resumeIndex = nil
                                        draft.seed = UInt64.random(in: 1...UInt64(UInt32.max))
                                        draftName = session.name; sheet = true
                                    }.disabled(store.busy)
                                    Button("Delete Scan", role: .destructive) { store.deleteSession(session.id) }
                                        .disabled(session.id == store.activeID)
                                }
                        }
                    }
                }.listStyle(.sidebar)
                Divider()
                HStack(spacing: 7) {
                    Circle().fill(store.installed ? .green : .orange).frame(width: 6, height: 6)
                    Text(store.installed ? "masscan installed" : "masscan not found").font(.caption)
                    Spacer()
                    Text("0.1").font(.caption).foregroundStyle(.tertiary)
                }.foregroundStyle(.secondary).padding(16)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 245, max: 300)
        } detail: {
            VStack(spacing: 0) {
                if let session = store.selected { scanDetail(session) }
                else { welcome }
            }
            .navigationTitle(store.selected?.name ?? "Masscan Studio")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button(action: newScan) { Label("New Scan", systemImage: "plus") }.disabled(store.busy)
                }
                ToolbarItem {
                    Menu {
                        Button("Export CSV…") { store.export(json: false, rows: rows) }
                        Button("Export JSON…") { store.export(json: true, rows: rows) }
                    } label: { Label("Export", systemImage: "square.and.arrow.up") }
                        .disabled(rows.isEmpty)
                }
            }
        }
        .sheet(isPresented: $sheet) {
            ConfigurationView(config: draft, name: draftName).environmentObject(store)
        }
        .onReceive(NotificationCenter.default.publisher(for: .newScan)) { _ in newScan() }
        .alert("Masscan Studio", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("OK") { store.error = nil }
        } message: { Text(store.error ?? "") }
    }
    private var welcome: some View {
        VStack(spacing: 22) {
            Spacer()
            ZStack {
                Circle().fill(.teal.opacity(0.06)).frame(width: 150, height: 150)
                Circle().stroke(.teal.opacity(0.15), lineWidth: 1).frame(width: 120, height: 120)
                Circle().stroke(.teal.opacity(0.2), lineWidth: 1).frame(width: 85, height: 85)
                Image(systemName: "dot.radiowaves.left.and.right").font(.system(size: 42, weight: .light)).foregroundStyle(.teal)
            }
            VStack(spacing: 10) {
                Text("A clear view of your network.").font(.system(size: 28, weight: .semibold))
                Text("Find open ports, follow results as they arrive,\nand keep every scan in one place.")
                    .font(.body).foregroundStyle(.secondary).multilineTextAlignment(.center).lineSpacing(4)
            }
            Button(action: newScan) { Label("New Scan", systemImage: "plus").padding(.horizontal, 14).padding(.vertical, 5) }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(store.busy)
            Text("⌘N to start a new scan").font(.caption).foregroundStyle(.tertiary)
            Spacer()
            HStack(spacing: 32) {
                Label("Live results", systemImage: "waveform.path")
                Label("Saved profiles", systemImage: "slider.horizontal.3")
                Label("CSV & JSON", systemImage: "square.and.arrow.up")
            }.font(.caption).foregroundStyle(.secondary).padding(.bottom, 35)
            if !store.installed {
                Text("Install the scanner with: brew install masscan")
                    .font(.system(.callout, design: .monospaced)).textSelection(.enabled).padding(.bottom, 24)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func scanDetail(_ session: ScanSession) -> some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(session.config.targets).font(.title2.weight(.semibold)).lineLimit(2).textSelection(.enabled)
                        Text("TCP \(session.config.ports)  ·  \(session.config.rate.formatted()) packets/s limit")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label(session.status, systemImage: session.status == "Completed" ? "checkmark.circle.fill" : "circle.fill")
                        .font(.caption.weight(.medium)).foregroundStyle(statusColor(session.status))
                        .padding(.horizontal, 11).padding(.vertical, 7)
                        .background(statusColor(session.status).opacity(0.09), in: Capsule())
                    if session.id == store.activeID {
                        Button { store.stop() } label: { Label("Pause", systemImage: "pause.fill") }
                            .disabled(session.status == "Stopping")
                    } else if session.config.resumeIndex != nil {
                        Button { store.resumeSelected() } label: { Label("Resume", systemImage: "play.fill") }
                            .disabled(store.busy)
                    }
                }
                HStack(spacing: 0) {
                    metric("OPEN PORTS", "\(session.results.count)", "network")
                    metric("HOSTS", "\(Set(session.results.map(\.ip)).count)", "desktopcomputer")
                    metric("PROGRESS", String(format: "%.1f%%", session.percent), "chart.bar")
                    metric(session.id == store.activeID ? "LIVE RATE" : "STARTED",
                           session.id == store.activeID ? "\(Int(store.rate).formatted()) pps" :
                            session.date.formatted(date: .omitted, time: .shortened), "clock")
                }
                if session.id == store.activeID {
                    VStack(alignment: .leading, spacing: 6) {
                        ProgressView(value: session.percent, total: 100)
                        Text(store.remaining).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }.padding(24)
            Divider()
            HStack(spacing: 12) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter by IP, port or service hint", text: $search).textFieldStyle(.plain)
                Text("\(rows.count) results").font(.caption).foregroundStyle(.secondary)
                Button { showLog.toggle() } label: { Image(systemName: "terminal") }
                    .help("Show scan log").buttonStyle(.borderless)
            }.padding(.horizontal, 20).padding(.vertical, 12)
            Table(rows, selection: $selectedRows, sortOrder: $sortOrder) {
                TableColumn("IP address", value: \.ipSort) { row in
                    Text(row.ip).font(.system(.body, design: .monospaced))
                }.width(min: 145, ideal: 180)
                TableColumn("Port", value: \.port) { row in
                    Text(String(row.port)).font(.system(.body, design: .monospaced))
                }.width(min: 60, ideal: 80)
                TableColumn("Protocol", value: \.proto) { row in Text(row.proto.uppercased()).foregroundStyle(.secondary) }
                    .width(min: 65, ideal: 85)
                TableColumn("Service hint", value: \.service) { row in Text(row.service) }
                TableColumn("Discovered", value: \.discoveredAt) { row in
                    Text(row.discoveredAt, format: .dateTime.hour().minute().second()).foregroundStyle(.secondary)
                }.width(min: 100, ideal: 120)
            }
            .contextMenu {
                Button("Copy IP Addresses") {
                    let addresses = Array(Set(rows.filter { selectedRows.contains($0.id) }.map(\.ip))).sorted()
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(addresses.joined(separator: "\n"), forType: .string)
                }.disabled(selectedRows.isEmpty)
            }
            .overlay {
                if rows.isEmpty {
                    ContentUnavailableView(
                        search.isEmpty ? (session.status == "Completed" ? "No open ports found" : "No open ports yet") : "No matching results",
                        systemImage: search.isEmpty ? "network" : "magnifyingglass",
                        description: Text(search.isEmpty ?
                            (session.status == "Completed" ? "This scan completed without reporting an open port." : "Discovered ports will appear here as the scan runs.") :
                            "Try a different IP address, port or service."))
                }
            }
            if showLog || session.status == "Failed" {
                Divider()
                ScrollView {
                    Text(session.log.isEmpty ? "No diagnostic output." : session.log)
                        .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }.frame(height: 150).background(.background.secondary)
            }
            Divider()
            HStack {
                Text("Service names are port-based hints, not verified identification.")
                Spacer()
                if !search.isEmpty { Text("Export uses filtered results") }
            }.font(.caption2).foregroundStyle(.secondary).padding(10)
        }
    }
    private func metric(_ label: String, _ value: String, _ icon: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(label, systemImage: icon).font(.system(size: 10, weight: .semibold)).tracking(0.7).foregroundStyle(.secondary)
            Text(value).font(.system(size: 25, weight: .medium, design: .rounded)).monospacedDigit()
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func newScan() {
        guard !store.busy else { return }
        draft = ScanConfiguration(); draftName = ""; sheet = true
    }
    private func statusColor(_ status: String) -> Color {
        switch status {
        case "Completed": return .green
        case "Failed", "Interrupted": return .orange
        case "Scanning", "Authorizing", "Stopping": return .teal
        default: return .secondary
        }
    }
}
