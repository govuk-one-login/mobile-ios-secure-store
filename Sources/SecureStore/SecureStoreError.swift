import Foundation
import LocalAuthentication

public enum SecureStoreError: Error {
    case unableToRetrieveFromUserDefaults
    case cantGetPublicKeyFromPrivateKey
    case cantDeleteKey
    case cantStoreKey
    case cantRetrieveKey
    case cantEncryptData
    case cantDecryptData
    case biometricsCancelled
    case biometricsFailed
    case cantEncodeData
    case cantDecodeData
    case cantFormatData

    static func biometricErrorHandling(error: CFError?, defaultError: Self) -> Error {
        guard let error else {
            return defaultError
        }
        let code = CFErrorGetCode(error)
        let domain = String(CFErrorGetDomain(error))
        
        switch (code, domain) {
        case (LAError.userCancel.rawValue, LAErrorDomain),
            (LAError.systemCancel.rawValue, LAErrorDomain):
            return self.biometricsCancelled
        // Transforming the below errors to `.biometricCancelled` as part of tactical fix for DCMAW-17186
        // This will be updated during in strategic fix planned for the new year
        case (LAError.notInteractive.rawValue /* -1004 */, LAErrorDomain),
            (LAError.userFallback.rawValue /* -3 */, LAErrorDomain),
            (LAError.authenticationFailed.rawValue /* -1 */, LAErrorDomain),
            (6, LAErrorDomain),
            (-1000, LAErrorDomain):
            return self.biometricsCancelled
        default:
            return error
        }
    }
}

/// Use as: error.localizedDescription
extension SecureStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unableToRetrieveFromUserDefaults:
            return "Error while retrieving item from User Defaults"
        case .cantGetPublicKeyFromPrivateKey:
            return "Error while getting public key from private key"
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
        case .biometricsCancelled:
            return "User or system cancelled the biometric prompt"
        case .biometricsFailed:
            return "Biometric authentication failed after multiple attempts or biometrics are not set up"
        case .cantEncodeData:
            return "Error while encoding data"
        case .cantDecodeData:
            return "Error while decoding data"
        case .cantFormatData:
            return "Error while formatting data"
        }
    }
}
