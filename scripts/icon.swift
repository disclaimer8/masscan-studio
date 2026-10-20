import AppKit
let destination = CommandLine.arguments[1]
let iconset = destination + "/AppIcon.iconset"
try FileManager.default.createDirectory(atPath: iconset, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let image = NSImage(size: NSSize(width: pixels, height: pixels))
        image.lockFocus()
        let context = NSGraphicsContext.current!.cgContext
        context.scaleBy(x: CGFloat(pixels) / 1024, y: CGFloat(pixels) / 1024)
        let background = NSBezierPath(roundedRect: NSRect(x: 52, y: 52, width: 920, height: 920), xRadius: 205, yRadius: 205)
        NSColor(calibratedRed: 0.035, green: 0.11, blue: 0.14, alpha: 1).setFill()
        background.fill()
        let teal = NSColor(calibratedRed: 0.27, green: 0.91, blue: 0.78, alpha: 1)
        for radius in [130.0, 245.0, 360.0] {
            let ring = NSBezierPath(ovalIn: NSRect(x: 512-radius, y: 512-radius, width: radius*2, height: radius*2))
            teal.withAlphaComponent(0.33).setStroke()
            ring.lineWidth = 10; ring.stroke()
        }
        let ray = NSBezierPath()
        ray.move(to: NSPoint(x: 512, y: 512)); ray.line(to: NSPoint(x: 758, y: 758))
        teal.setStroke(); ray.lineWidth = 24; ray.lineCapStyle = .round; ray.stroke()
        for (x, y, radius) in [(512.0, 512.0, 26.0), (300, 395, 23), (665, 680, 29), (676, 276, 20)] {
            teal.setFill()
            NSBezierPath(ovalIn: NSRect(x: x-radius, y: y-radius, width: radius*2, height: radius*2)).fill()
        }
        image.unlockFocus()
        let data = NSBitmapImageRep(data: image.tiffRepresentation!)!.representation(using: .png, properties: [:])!
        let suffix = scale == 1 ? "" : "@2x"
        try data.write(to: URL(fileURLWithPath: "\(iconset)/icon_\(size)x\(size)\(suffix).png"))
    }
}
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", iconset, "-o", destination + "/AppIcon.icns"]
try process.run(); process.waitUntilExit()
guard process.terminationStatus == 0 else { exit(1) }
