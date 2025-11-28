import Foundation
import LocalAuthentication

public enum SecureStoreError: Error {
    case unableToRetrieveFromUserDefaults
    case cantGetPublicKeyFromPrivateKey
    case cantDeleteKey
    case cantStoreKey
    case cantRetrieveKey
    case cantEncryptData
    case cantEncodeData
    case cantDecodeData
    case cantFormatData
    
    // LAError.Code transformations
    // https://developer.apple.com/documentation/localauthentication/laerror-swift.struct/code
    case biometricsFailed
    case biometricsCancelled
    case userFallback
    case passcodeNotSet
    case biometryNotAvailable
    case biometryNotEnrolled
    case biometryLockout
    
    case invalidContext
    case notInteractive
    case viewServiceIntialisationFailure
    case serviceConnectionInvalidated
    case cantDecryptData
    case defaultDecryptionError

    static func biometricErrorHandling(error: CFError?, defaultError: Self) -> Error {
        guard let error else {
            return defaultError
        }
        let code = CFErrorGetCode(error), domain = String(CFErrorGetDomain(error))
        switch (code, domain) {
        case (LAError.authenticationFailed.rawValue /* -1 */, LAErrorDomain):
            return self.biometricsFailed
        case (LAError.userCancel.rawValue /* -2 */, LAErrorDomain),
            (LAError.systemCancel.rawValue /* -3 */, LAErrorDomain):
            return self.biometricsCancelled
        case (LAError.userFallback.rawValue /* -4 */, LAErrorDomain):
            return self.userFallback
        case (LAError.passcodeNotSet.rawValue /* -5 */, LAErrorDomain):
            return self.passcodeNotSet
        case (LAError.biometryNotAvailable.rawValue /* -6 */, LAErrorDomain):
            return self.biometryNotAvailable
        case (LAError.biometryNotEnrolled.rawValue /* -7 */, LAErrorDomain):
            return self.biometryNotEnrolled
        case (LAError.biometryLockout.rawValue /* -8 */, LAErrorDomain):
            return self.biometryLockout
        case (LAError.appCancel.rawValue /* -9 */, LAErrorDomain):
            return self.biometricsCancelled
        case (LAError.invalidContext.rawValue /* -10 */, LAErrorDomain):
            return self.invalidContext
        case (LAError.notInteractive.rawValue /* -1004 */, LAErrorDomain):
            return self.notInteractive
        case (6, LAErrorDomain):
            return self.viewServiceIntialisationFailure
        case (-1000, LAErrorDomain):
            return self.serviceConnectionInvalidated
        // double check if you can match the error code to a specific NSOSStatus error code
        case (-50, NSOSStatusErrorDomain):
            return self.cantDecryptData
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
            "Error while retrieving item from User Defaults."
        case .cantGetPublicKeyFromPrivateKey:
            "Error while getting public key from private key."
        case .cantDeleteKey:
            "Error while deleting key from the keychain."
        case .cantStoreKey:
            "Error while storing key to the keychain."
        case .cantRetrieveKey:
            "Error while retrieving key from the keychain."
        case .cantEncryptData:
            "Error while encrypting data."
        case .cantEncodeData:
            "Error while encoding data."
        case .cantDecodeData:
            "Error while decoding data."
        case .cantFormatData:
            "Error while formatting data."
        
        case .biometricsFailed:
            "Biometric authentication failed after multiple attempts or biometrics are not set up."
        case .biometricsCancelled:
            "User or system cancelled the biometric prompt."
        case .userFallback:
            #"The user tapped the "Fallback" button."#
        case .passcodeNotSet:
            "A passcode is not set on the device."
        case .biometryNotAvailable:
            "Biometry is not available on the device."
        case .biometryNotEnrolled:
            "The user has no enrolled biometric identities."
        case .biometryLockout:
            "Too many failed biometry attempts have locked the feature."

        case .invalidContext:
            "The authentication context is invalid."
        case .notInteractive:
            "Displaying the authentication user interface is forbidden."
        case .viewServiceIntialisationFailure:
            "The view service failed to initialise."
        case .serviceConnectionInvalidated:
            "The service connection was invalidated."
        case .cantDecryptData:
            "Error while decrypting data."
        case .defaultDecryptionError:
            "Default error for cannot decrypt data. Used when there was no error passed."
        }
    }
}
