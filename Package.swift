// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecureStore",
    platforms: [.iOS(.v13), .macOS(.v11)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "SecureStore",
            targets: ["SecureStore"]
        ),
        .library(
            name: "CryptoService",
            targets: ["CryptoService"]
        )
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt", from: "5.3.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SecureStore"
        ),
        .testTarget(
            name: "SecureStoreTests",
            dependencies: ["SecureStore"]
        ),
        
        .target(
            name: "CryptoService",
            dependencies: [
                .product(name: "BigInt", package: "BigInt")
            ]
        ),
        .testTarget(
            name: "CryptoServiceTests",
            dependencies: ["CryptoService"]
        )
    ]
)
