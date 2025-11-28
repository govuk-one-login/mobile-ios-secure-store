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
    case invalidContext
    case notInteractive

    static func biometricErrorHandling(error: CFError?, defaultError: Self) -> Error {
        guard let error else {
            return defaultError
        }
        let code = CFErrorGetCode(error)
        switch code {
        case LAError.notInteractive.rawValue:
            return self.notInteractive
        case LAError.invalidContext.rawValue:
            return self.invalidContext
        case LAError.authenticationFailed.rawValue:
            return self.biometricsFailed
        case LAError.userCancel.rawValue, LAError.systemCancel.rawValue:
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
        case .invalidContext:
            return "view context was invalidated"
        case .notInteractive:
            return "the app is not interactive to perform local auth"
        }
    }
}
