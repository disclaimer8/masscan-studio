#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift build -c release
bundle="$PWD/dist/Masscan Studio.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp .build/release/MasscanStudio "$bundle/Contents/MacOS/MasscanStudio"
cp .build/release/ScanHelper "$bundle/Contents/MacOS/ScanHelper"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Masscan Studio</string>
<key>CFBundleDisplayName</key><string>Masscan Studio</string>
<key>CFBundleIdentifier</key><string>local.masscan.studio</string>
<key>CFBundleExecutable</key><string>MasscanStudio</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSLocalNetworkUsageDescription</key><string>Masscan Studio scans the network targets you select and communicates with its local scan runner.</string>
<key>NSHumanReadableCopyright</key><string>Masscan Studio. Uses your separately installed masscan.</string>
</dict></plist>
PLIST
swift scripts/icon.swift "$bundle/Contents/Resources"
codesign --force --sign - "$bundle/Contents/MacOS/ScanHelper"
codesign --force --sign - "$bundle"
codesign --verify --deep --strict "$bundle"
printf '%s\n' "$bundle"
