// swift-tools-version:5.2

import Foundation
import PackageDescription

// MARK: Definitions

let package = Package(
    name: "SocialGraphKit",
    // Supported versions.
    platforms: [.iOS("16.0"),
                .macOS("10.15"),
                .tvOS("13.0"),
                .watchOS("6.0")],
    // Exposed libraries.
    products: [.library(name: "SocialGraphKit",
                        targets: ["SocialGraphKit"]),
               .library(name: "SocialGraphKitCrypto",
                        targets: ["SocialGraphKitCrypto"])],
    // Package dependencies.
    dependencies: [.package(url: "https://github.com/sbertix/ComposableRequest", .upToNextMinor(from: "5.3.1")),
                   .package(url: "https://github.com/sbertix/SwCrypt.git", .upToNextMinor(from: "5.1.0"))],
    // All targets.
    targets: [.target(name: "SocialGraphKit",
                      dependencies: [.product(name: "Requests", package: "ComposableRequest"),
                                     .product(name: "Storage", package: "ComposableRequest")]),
              .target(name: "SocialGraphKitCrypto",
                      dependencies: ["SocialGraphKit",
                                     .product(name: "StorageCrypto", package: "ComposableRequest"),
                                     .product(name: "SwCrypt", package: "SwCrypt")]),
              .testTarget(name: "SocialGraphKitTests",
                          dependencies: ["SocialGraphKit", "SocialGraphKitCrypto"])]
)

if ProcessInfo.processInfo.environment["TARGETING_WATCHOS"] == "true" {
    // #workaround(xcodebuild -version 11.6, Test targets don’t work on watchOS.) @exempt(from: unicode)
    package.targets.removeAll(where: { $0.isTest })
}
