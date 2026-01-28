import Foundation
import GDSUtilities
import LocalAuthentication

extension SecureStoreError where Kind == ErrorKind.SecureStore {
    public init(
        _ kind: ErrorKind.SecureStore,
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
        
        self.init(
            kind: kind,
            reason: errorReason,
            endpoint: endpoint,
            statusCode: statusCode,
            file: file,
            function: function,
            line: line,
            resolvable: resolvable,
            originalError: originalError,
            additionalParameters: additionalParameters
        )
    }
    
    static func biometricErrorHandling(error: CFError?, defaultError: Self) -> Error {
        guard let error else {
            return defaultError
        }
        let code = CFErrorGetCode(error)
        let domain = String(CFErrorGetDomain(error))
        
        switch (code, domain) {
        // LAErrors mapped to 'recoverable'
        case (LAError.authenticationFailed.rawValue /* -1 */, LAErrorDomain),
            (LAError.userFallback.rawValue /* -3 */, LAErrorDomain),
            (LAError.systemCancel.rawValue /* -4 */, LAErrorDomain),
            (LAError.appCancel.rawValue /* -9 */, LAErrorDomain),
            (LAError.invalidContext.rawValue /* -10 */, LAErrorDomain),
            (LAError.biometryNotAvailable.rawValue, LAErrorDomain),
            (LAError.biometryNotEnrolled.rawValue, LAErrorDomain),
            (LAError.biometryLockout.rawValue, LAErrorDomain),
            (LAError.notInteractive.rawValue /* -1004 */, LAErrorDomain),
            (6, LAErrorDomain),
            (-1000, LAErrorDomain):
            return SecureStoreError(
                .recoverable,
                originalError: error
            )

        // LAEerrors mapped to 'userCancelled'
        case (LAError.userCancel.rawValue /* -2 */, LAErrorDomain):
            return SecureStoreError(
                .userCancelled,
                originalError: error
            )

        // LAErrors mapped to 'unrecoverable'
        case (-50, NSOSStatusErrorDomain):
            return SecureStoreError(
                .unrecoverable,
                originalError: error
            )

        // LAErrors mapped to `noLocalAuthEnrolled`
        case (LAError.passcodeNotSet.rawValue /* -5 */, LAErrorDomain):
            return SecureStoreError(
                .noLocalAuthEnrolled,
                originalError: error
            )
        default:
            return error
        }
    }
    
    private static func errorReason(for kind: ErrorKind.SecureStore) -> String {
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
