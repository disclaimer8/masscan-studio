import SwiftUI
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    var store: SessionStore?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let store, store.busy else { store?.shutdown(); return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "Stop the active scan and quit?"
        alert.informativeText = "The current results are saved. Keep the app open to pause the scan and save a resume checkpoint."
        alert.addButton(withTitle: "Keep Scanning")
        alert.addButton(withTitle: "Stop and Quit")
        guard alert.runModal() == .alertSecondButtonReturn else { return .terminateCancel }
        store.shutdown()
        return .terminateNow
    }
}

@main
struct MasscanStudioApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var store = SessionStore()
    var body: some Scene {
        Window("Masscan Studio", id: "main") {
            ContentView()
                .environmentObject(store)
                .frame(minWidth: 1000, minHeight: 680)
                .tint(.teal)
                .onAppear { delegate.store = store }
        }
        .defaultSize(width: 1180, height: 780)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Scan…") { NotificationCenter.default.post(name: .newScan, object: nil) }
                    .keyboardShortcut("n")
                    .disabled(store.busy)
            }
        }
    }
}
extension Notification.Name { static let newScan = Notification.Name("newScan") }
