// swift-tools-version: 5.8
import PackageDescription

let package = Package(
    name: "AveroxCrypto",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
        .watchOS(.v8),
        .tvOS(.v15)
    ],
    products: [
        .library(
            name: "AveroxCrypto",
            targets: ["AveroxCrypto"]
        ),
    ],
    dependencies: [
        // Government-approved cryptographic dependencies
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.61.1"),
        .package(url: "https://github.com/apple/swift-log.git", exact: "1.5.3")
    ],
    targets: [
        .target(
            name: "AveroxCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log")
            ],
            swiftSettings: [
                .define("GOVERNMENT_COMPLIANCE"),
                .define("FIPS_MODE", .when(configuration: .release))
            ]
        ),
        .testTarget(
            name: "AveroxCryptoTests",
            dependencies: ["AveroxCrypto"]
        ),
    ]
)
