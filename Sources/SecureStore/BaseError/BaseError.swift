import CryptoKit
import Foundation
import GDSAnalytics

public protocol BaseError:
    Equatable,
    LoggableError,
    CustomNSError,
    CustomDebugStringConvertible
    where Kind: AnyErrorKind {
    associatedtype Kind
    var kind: Kind { get }
    var reason: String? { get }
    var endpoint: String? { get }
    var statusCode: Int? { get }
    var file: String { get }
    var function: String { get }
    var line: Int { get }
    var resolvable: Bool { get }
    var originalError: Error? { get }
    var additionalParameters: [String: any Sendable] { get }
}

// Implementation for `Equatable` and pattern matching
extension BaseError {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.kind == rhs.kind
    }

    public static func ~= (rhs: Self, lhs: Error) -> Bool {
        (lhs as? Self) == rhs
    }
}

// Needed for conformance to AnyErrorKind
extension BaseError {
    public var logToCrashlytics: Bool {
        kind.logToCrashlytics
    }
}

/// Needed for conformance to LoggableError
extension BaseError {
    public var hash: String? {
        var string: String = ""
        if let statusCode {
            string += String(statusCode)
        }
        string += "_\(endpoint ?? file)"
        let digest = Insecure.MD5.hash(data: string.data(using: .utf8) ?? Data())

        return digest.map {
            String(format: "%02hhx", $0)
        }.joined()
    }
}

/// CustomNSError properties
extension BaseError {
    public static var errorDomain: String {
        String(describing: self.Kind)
    }

    public var errorUserInfo: [String: Any] {
        var originalErrorString: String? = self.originalError?.localizedDescription
        var originalKind: (any AnyErrorKind)?

        if let original = originalError as? (any BaseError) {
            originalErrorString = original.debugDescription
            originalKind = original.kind
        }

        let params: [String: Any?] = [
            "kind": self.kind,
            "reason": self.reason,
            "endpoint": self.endpoint,
            "statusCode": self.statusCode,
            "file": self.file.components(separatedBy: "/").last,
            "function": self.function,
            "line": self.line,
            "resolvable": String(self.resolvable),
            "originalErrorKind": originalKind,
            "originalError": originalErrorString
        ]

        let paramsToLog = params.merging(additionalParameters) { lhs, _ in
            lhs
        }

        return paramsToLog.compactMapValues { $0 }
    }

    public var errorCode: Int {
        // NOTE: This is not perfect but will help group errors better.
        statusCode ?? self.line
    }
}

/// CustomDebugStringConvertable properties
extension BaseError {
    public var debugDescription: String {
        var description: String = ""
        description.append(self.reason ?? self.kind.rawValue)

        if let originalError = self.originalError as? any BaseError {
            description.append(" - (\(originalError.debugDescription))")
        }

        return description
    }
}
