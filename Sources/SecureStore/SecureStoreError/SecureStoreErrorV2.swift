import Foundation
import GDSUtilities
import LocalAuthentication

public typealias SecureStoreErrorV2 = GDSSecureStoreError<SecureStoreErrorKind>

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
        additionalParameters: [String: any Sendable] = [:]
    ) {
        self.kind = kind
        // Use the provided reason or fall back to a default based on the kind
        self.reason = reason ?? SecureStoreErrorV2.errorReason(for: kind)
        self.endpoint = endpoint
        self.statusCode = statusCode
        self.file = file
        self.function = function
        self.line = line
        self.resolvable = resolvable
        self.originalError = originalError
        self.additionalParameters = additionalParameters
    }
    
    // swiftlint:disable:next function_body_length
    static func biometricErrorHandling(error: NSError?) -> SecureStoreErrorV2 {
        guard let error else {
            return SecureStoreErrorV2(
                .noResultOrError
            )
        }
        
        guard let laError = error as? LAError else {
            if (error.code, error.domain) == (-50, NSOSStatusErrorDomain) {
                return SecureStoreErrorV2(
                    .cantDecryptData,
                    reason: error.localizedDescription,
                    originalError: error
                )
            } else {
                return SecureStoreErrorV2(
                    .unknownNSError,
                    reason: error.localizedDescription,
                    originalError: error
                )
            }
        }
        
        switch laError.code {
        case .authenticationFailed /* -1 */:
            return SecureStoreErrorV2(
                .authenticationFailed,
                reason: error.localizedDescription,
                originalError: error
            )
        case .userCancel /* -2 */:
            return SecureStoreErrorV2(
                .userCancel,
                reason: error.localizedDescription,
                originalError: error
            )
        case .userFallback /* -3 */:
            return SecureStoreErrorV2(
                .userFallback,
                reason: error.localizedDescription,
                originalError: error
            )
        case .systemCancel /* -4 */:
            return SecureStoreErrorV2(
                .systemCancel,
                reason: error.localizedDescription,
                originalError: error
            )
        case .passcodeNotSet /* -5 */:
            return SecureStoreErrorV2(
                .passcodeNotSet,
                reason: error.localizedDescription,
                originalError: error
            )
        case .biometryNotAvailable, .touchIDNotAvailable /* -6 */:
            return SecureStoreErrorV2(
                .biometryNotAvailable,
                reason: error.localizedDescription,
                originalError: error
            )
        case .biometryNotEnrolled, .touchIDNotEnrolled /* -7 */:
            return SecureStoreErrorV2(
                .biometryNotEnrolled,
                reason: error.localizedDescription,
                originalError: error
            )
        case .biometryLockout, .touchIDLockout /* -8 */:
            return SecureStoreErrorV2(
                .biometryLockout,
                reason: error.localizedDescription,
                originalError: error
            )
        case .appCancel /* -9 */:
            return SecureStoreErrorV2(
                .appCancel,
                reason: error.localizedDescription,
                originalError: error
            )
        case .invalidContext /* -10 */:
            return SecureStoreErrorV2(
                .invalidContext,
                reason: error.localizedDescription,
                originalError: error
            )
        case .companionNotAvailable /* -11 */:
            return SecureStoreErrorV2(
                .companionNotAvailable,
                reason: error.localizedDescription,
                originalError: error
            )
        #if os(macOS)
        case .watchNotAvailable /* -11 */:
            return SecureStoreErrorV2(
                .watchNotAvailable,
                reason: error.localizedDescription,
                originalError: error
            )
        case .biometryNotPaired /* -12 */:
            return SecureStoreErrorV2(
                .biometryNotPaired,
                reason: error.localizedDescription,
                originalError: error
            )
        case .biometryDisconnected /* -13 */:
            return SecureStoreErrorV2(
                .biometryDisconnected,
                reason: error.localizedDescription,
                originalError: error
            )
        case .invalidDimensions /* -14 */:
            return SecureStoreErrorV2(
                .invalidDimensions,
                reason: error.localizedDescription,
                originalError: error
            )
        #endif
        case .notInteractive /* -1004 */:
            return SecureStoreErrorV2(
                .notInteractive,
                reason: error.localizedDescription,
                originalError: error
            )
        case LAError.Code(rawValue: 4):
            return SecureStoreErrorV2(
                .invalidatedByHandleRequest,
                reason: error.localizedDescription,
                originalError: error
            )
        case LAError.Code(rawValue: 6):
            return SecureStoreErrorV2(
                .viewServiceInitializationFailure,
                reason: error.localizedDescription,
                originalError: error
            )
        case LAError.Code(rawValue: -1000):
            return SecureStoreErrorV2(
                .authenticationTimedOut,
                reason: error.localizedDescription,
                originalError: error
            )
        case LAError.Code(rawValue: -1003):
            return SecureStoreErrorV2(
                .uiActivationTimedOut,
                reason: error.localizedDescription,
                originalError: error
            )
        @unknown default:
            return SecureStoreErrorV2(
                .unknownLAError,
                reason: error.localizedDescription,
                originalError: error
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
