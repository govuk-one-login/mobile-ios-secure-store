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
        case (LAError.userCancel.rawValue, LAErrorDomain),
            (LAError.systemCancel.rawValue, LAErrorDomain):
            return SecureStoreError(
                .biometricsCancelled,
                originalError: error
            )
        // Transforming the below errors to `.biometricCancelled` as part of tactical fix for DCMAW-17186
        // This will be updated during in strategic fix planned for the new year
        case (LAError.notInteractive.rawValue /* -1004 */, LAErrorDomain),
            (LAError.userFallback.rawValue /* -3 */, LAErrorDomain),
            (LAError.authenticationFailed.rawValue /* -1 */, LAErrorDomain),
            (6, LAErrorDomain),
            (-1000, LAErrorDomain):
            return SecureStoreError(
                .biometricsCancelled,
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
            return "A recoverable error has been thrown from LocalAuthentication package"
        case .unreoverable:
            return "A unrecoverable error has been thrown from LocalAuthentication package"
        case .biometricsCancelled:
            return "User or system cancelled the biometric prompt"
        }
    }
}

extension SecureStoreError where Kind.RawValue == String {
    public var localizedDescription: String {
        kind.rawValue
    }
}
