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
        // Use the provided reason or fall back to a default based on the kind
        self.reason = reason ?? SecureStoreError.errorReason(for: kind)
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
                return SecureStoreError(
                    .cantDecryptData,
                    reason: error.localizedDescription,
                    originalError: error,
                    additionalParameters: error.userInfo
                )
            } else {
                return SecureStoreError(
                    .unknownNSError,
                    reason: error.localizedDescription,
                    originalError: error,
                    additionalParameters: error.userInfo
                )
            }
        }
        
        switch laError.code {
        case .authenticationFailed: // -1
            return SecureStoreError(
                .authenticationFailed,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .userCancel: // -2
            return SecureStoreError(
                .userCancel,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .userFallback: // -3
            return SecureStoreError(
                .userFallback,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .systemCancel: // -4
            return SecureStoreError(
                .systemCancel,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .passcodeNotSet: // -5
            return SecureStoreError(
                .passcodeNotSet,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .biometryNotAvailable, .touchIDNotAvailable: // -6
            return SecureStoreError(
                .biometryNotAvailable,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .biometryNotEnrolled, .touchIDNotEnrolled: // -7
            return SecureStoreError(
                .biometryNotEnrolled,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .biometryLockout, .touchIDLockout: // -8
            return SecureStoreError(
                .biometryLockout,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .appCancel: // -9
            return SecureStoreError(
                .appCancel,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .invalidContext: // -10
            return SecureStoreError(
                .invalidContext,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .companionNotAvailable: // -11
            return SecureStoreError(
                .companionNotAvailable,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        #if os(macOS)
        case .watchNotAvailable: // -11
            return SecureStoreError(
                .watchNotAvailable,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .biometryNotPaired: // -12
            return SecureStoreError(
                .biometryNotPaired,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .biometryDisconnected: // -13
            return SecureStoreError(
                .biometryDisconnected,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case .invalidDimensions: // -14
            return SecureStoreError(
                .invalidDimensions,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        #endif
        case .notInteractive: // -1004
            return SecureStoreError(
                .notInteractive,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case LAError.Code(rawValue: 4):
            return SecureStoreError(
                .invalidatedByHandleRequest,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case LAError.Code(rawValue: 6):
            return SecureStoreError(
                .viewServiceInitializationFailure,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case LAError.Code(rawValue: -1000):
            return SecureStoreError(
                .uiActivationTimedOut,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        case LAError.Code(rawValue: -1003):
            return SecureStoreError(
                .authenticationTimedOut,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        @unknown default:
            return SecureStoreError(
                .unknownLAError,
                reason: error.localizedDescription,
                originalError: error,
                additionalParameters: error.userInfo
            )
        }
    }
    
    // swiftlint:disable:next function_body_length
    private static func errorReason(for kind: some GDSErrorKind) -> String? {
        guard let kind = kind as? SecureStoreErrorKind else {
            return nil
        }
        
        switch kind {
        case .unableToRetrieveFromUserDefaults:
            return "Error while retrieving item from User Defaults"
        case .cantDeleteKey:
            return "Error while deleting key from the keychain"
        case .cantStoreKey:
            return "Error while storing key to the keychain"
        case .cantRetrieveKey:
            return "Error while retrieving key from the keychain"
        case .cantEncryptData:
            return "Error while encrypting data"
        case .cantDecryptData:
            return "Error while decrypting data"
        case .cantEncodeData:
            return "Error while encoding data"
        case .cantDecodeData:
            return "Error while decoding data"
        case .cantFormatData:
            return "Error while formatting data"
        case .authenticationFailed:
            return "User failed to provide valid credentials"
        case .userCancel:
            return "User cancelled the biometric prompt"
        case .userFallback:
            return "No fallback is available for the authentication policy"
        case .systemCancel:
            return "System cancelled authentication"
        case .passcodeNotSet:
            return "A passcode isn't set on the device"
        case .biometryNotAvailable:
            return "No biometry available on the device"
        case .biometryNotEnrolled:
            return "Biometry is not enrolled on the device"
        case .biometryLockout:
            return "Biometry is locked out"
        case .appCancel:
            return "App cancelled authentication"
        case .invalidContext:
            return "The context was previously invalidated"
        case .companionNotAvailable:
            return "No paired companion device nearby"
        case .watchNotAvailable:
            return "No paired watch nearby"
        case .biometryNotPaired:
            return "Device supports biometry only via removable accessories and no accessory has been paired"
        case .biometryDisconnected:
            return "Device supports biometry only via removable accessories and the paired accessory is not connected."
        case .invalidDimensions:
            return "Dimensions of embedded UI are invalid"
        case .notInteractive:
            return "Displaying the required authentication user interface is forbidden"
        case .invalidatedByHandleRequest:
            return "Invalidated by handle request"
        case .viewServiceInitializationFailure:
            return "Invalidated due to view service initialization failure"
        case .authenticationTimedOut:
            return "Authentication timed out"
        case .uiActivationTimedOut:
            return "UI activation timed out after 5 seconds"
        case .unknownLAError:
            return "Unknown LAError"
        case .unknownNSError:
            return "Unknow NSError"
        case .noResultOrError:
            return "No result or error returned"
        }
    }
}
