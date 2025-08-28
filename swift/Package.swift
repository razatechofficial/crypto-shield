// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "salman-40-crypto-sdk",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [
        .library(name: "AveroxCrypto", targets: ["AveroxCrypto"])
    ],
    targets: [
        .target(name: "AveroxCrypto", dependencies: [])
    ]
)