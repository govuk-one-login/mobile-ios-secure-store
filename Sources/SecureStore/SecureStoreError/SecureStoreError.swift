import Foundation
import GDSUtilities
import LocalAuthentication

@available(*, deprecated, renamed: "SecureStoreError")
public typealias SecureStoreErrorV2 = SecureStoreError

public typealias SecureStoreError = GDSSecureStoreError<SecureStoreErrorKind>

// swiftlint:disable:next type_body_length
public struct GDSSecureStoreError<Kind: GDSErrorKind>: GDSError {
    public let kind: Kind
    public let reason: String?
    public let endpoint: String?
    public let statusCode: Int?
    public let file: String
    public let function: String
    public let line: Int
    public let resolvable: Bool
    public let originalError: Error?
    public let additionalParameters: [String: any Sendable]
    
    public init(
        _ kind: Kind,
        reason: String? = nil,
        endpoint: String? = nil,
        statusCode: Int? = nil,
        file: String = #file,
        function: String = #function,
        line: Int = #line,
        resolvable: Bool = true,
        originalError: Error? = nil,
        additionalParameters: [String: Any] = [:]
    ) {
        self.kind = kind
        self.reason = reason
        self.endpoint = endpoint
        self.statusCode = statusCode
        self.file = file
        self.function = function
        self.line = line
        self.resolvable = resolvable
        self.originalError = originalError
        self.additionalParameters = additionalParameters.compactMapValues { String(describing: $0) }
    }
    
    // swiftlint:disable:next function_body_length
    static func biometricErrorHandling(error: NSError?) -> SecureStoreError {
        guard let error else {
            return SecureStoreError(
                .noResultOrError
            )
        }
        
        guard let laError = error as? LAError else {
            if (error.code, error.domain) == (-50, NSOSStatusErrorDomain) {
                return SecureStoreError(.cantDecryptData, originalError: error)
            } else {
                return SecureStoreError(.unknownNSError, originalError: error)
            }
        }
        
        switch laError {
        case LAError.authenticationFailed:
            return SecureStoreError(.authenticationFailed, originalError: error)
        case LAError.userCancel:
            return SecureStoreError(.userCancel, originalError: error)
        case LAError.userFallback:
            return SecureStoreError(.userFallback, originalError: error)
        case LAError.systemCancel:
            return SecureStoreError(.systemCancel, originalError: error)
        case LAError.passcodeNotSet:
            return SecureStoreError(.passcodeNotSet, originalError: error)
        case LAError.biometryNotAvailable, LAError.biometryNotAvailable:
            return SecureStoreError(.biometryNotAvailable, originalError: error)
        case LAError.biometryNotEnrolled, LAError.biometryNotEnrolled:
            return SecureStoreError(.biometryNotEnrolled, originalError: error)
        case LAError.biometryLockout, LAError.biometryLockout:
            return SecureStoreError(.biometryLockout, originalError: error)
        case LAError.appCancel:
            return SecureStoreError(.appCancel, originalError: error)
        case LAError.invalidContext:
            return SecureStoreError(.invalidContext, originalError: error)
        case let error where error.code.rawValue == Int(kLAErrorCompanionNotAvailable):
            return SecureStoreError(.companionNotAvailable, originalError: error)
        #if os(macOS)
        case LAError.watchNotAvailable:
            return SecureStoreError(.watchNotAvailable, originalError: error)
        case LAError.biometryNotPaired:
            return SecureStoreError(.biometryNotPaired, originalError: error)
        case LAError.biometryDisconnected:
            return SecureStoreError(.biometryDisconnected, originalError: error)
        case LAError.invalidDimensions:
            return SecureStoreError(.invalidDimensions, originalError: error)
        #endif
        case LAError.notInteractive:
            return SecureStoreError(.notInteractive, originalError: error)
        case let error where error.code.rawValue == 4:
            return SecureStoreError(.invalidatedByHandleRequest, originalError: error)
        case let error where error.code.rawValue == 6:
            return SecureStoreError(.viewServiceInitializationFailure, originalError: error)
        case let error where error.code.rawValue == -1000:
            return SecureStoreError(.uiActivationTimedOut, originalError: error)
        case let error where error.code.rawValue == -1003:
            return SecureStoreError(.authenticationTimedOut, originalError: error)
        default:
            return SecureStoreError(.unknownLAError, originalError: error)
        }
    }
}
