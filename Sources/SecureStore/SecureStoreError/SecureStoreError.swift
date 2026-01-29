import Foundation
import GDSUtilities
import LocalAuthentication

public typealias SecureStoreError = GDSSecureStoreError<SecureStoreErrorKind>

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
        // Use the provided reason or fall back to a default based on the kind
        let errorReason = reason ?? SecureStoreError.errorReason(for: kind)
        
        self.kind = kind
        self.reason = errorReason
        self.endpoint = endpoint
        self.statusCode = statusCode
        self.file = file
        self.function = function
        self.line = line
        self.resolvable = resolvable
        self.originalError = originalError
        self.additionalParameters = additionalParameters
    }

    static func biometricErrorHandling(error: CFError?, defaultError: Self) -> Error {
        guard let error = error,
              String(CFErrorGetDomain(error)) == LAErrorDomain else {
            let code = CFErrorGetCode(error)
            let domain = String(CFErrorGetDomain(error))
            
            // Error that maps to 'unrecoverable'
            if (code, domain) == (-50, NSOSStatusErrorDomain) {
                return SecureStoreError(
                    .unrecoverable,
                    originalError: error
                )
            } else {
                return defaultError
            }
        }

        let laErrorCode = LAError.Code(rawValue: CFErrorGetCode(error))
        switch laErrorCode {
        // LAErrors mapped to 'userCancelled'
        case .userCancel /* -2 */:
            return SecureStoreError(
                .userCancelled,
                originalError: error
            )
        // LAErrors mapped to 'noLocalAuthEnrolled'
        case .passcodeNotSet /* -5 */:
            return SecureStoreError(
                .noLocalAuthEnrolled,
                originalError: error
            )
        // LAErrors mapped to 'recoverable'
        case .authenticationFailed /* -1 */,
             .userFallback /* -3 */,
             .systemCancel /* -4 */,
             .appCancel /* -9 */,
             .invalidContext /* -10 */,
             .biometryNotAvailable,
             .biometryNotEnrolled,
             .biometryLockout,
             .notInteractive /* -1004 */,
            LAError.Code(rawValue: 6),
            LAError.Code(rawValue: -1000):
            return SecureStoreError(
                .recoverable,
                originalError: error
            )
        default:
            return error
        }
    }
    
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
        case .recoverable:
            return "A recoverable error has been thrown"
        case .unrecoverable:
            return "A unrecoverable error has been thrown"
        case .userCancelled:
            return "User cancelled the biometric prompt"
        case .noLocalAuthEnrolled:
            return "Passcode is not set on the device"
        }
    }
}
