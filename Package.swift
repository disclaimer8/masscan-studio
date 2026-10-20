// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "MasscanStudio",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "MasscanStudio", targets: ["MasscanStudio"]),
        .executable(name: "ScanHelper", targets: ["ScanHelper"])
    ],
    targets: [
        .target(name: "ScanCore"),
        .executableTarget(name: "MasscanStudio", dependencies: ["ScanCore"]),
        .executableTarget(name: "ScanHelper", dependencies: ["ScanCore"]),
        .testTarget(name: "ScanCoreTests", dependencies: ["ScanCore"])
    ],
    swiftLanguageModes: [.v5]
)
