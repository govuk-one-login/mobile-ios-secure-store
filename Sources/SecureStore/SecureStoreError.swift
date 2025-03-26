import Foundation

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
    case cantEncodeOrDecodeData
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
        case .cantEncodeOrDecodeData:
            return "Error while encoding or decoding data"
        }
    }
}
