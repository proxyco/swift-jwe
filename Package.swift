// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JWE",
    platforms: [
        .macOS(.v12), .iOS(.v15),
    ],
    products: [
        .library(
            name: "swift-jwe",
            targets: ["JWE"]
        ),
    ],
    dependencies: [
        // For `X448` support
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "1.1.180")),
        // For `secp256k1` support
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMajor(from: "0.10.0")),
    ],
    targets: [
        .target(
            name: "JWE",
            dependencies: [
                "OpenSSL",
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ]
        ),
        .testTarget(
            name: "JWETests",
            dependencies: ["JWE"]
        ),
    ]
)
