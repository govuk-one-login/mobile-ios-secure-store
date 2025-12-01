import CoreFoundation
import LocalAuthentication
@testable import SecureStore
import Testing

// swiftlint:disable type_body_length
struct SecureStoreErrorTests {
    @Test
    // swiftlint:disable type_body_length
    func descriptions() {
        #expect(
            SecureStoreError.unableToRetrieveFromUserDefaults.localizedDescription ==
            "Error while retrieving item from User Defaults."
        )
        #expect(
            SecureStoreError.cantGetPublicKeyFromPrivateKey.localizedDescription ==
            "Error while getting public key from private key."
        )
        #expect(
            SecureStoreError.cantDeleteKey.localizedDescription ==
            "Error while deleting key from the keychain."
        )
        #expect(
            SecureStoreError.cantStoreKey.localizedDescription ==
            "Error while storing key to the keychain."
        )
        #expect(
            SecureStoreError.cantRetrieveKey.localizedDescription ==
            "Error while retrieving key from the keychain."
        )
        #expect(
            SecureStoreError.cantEncryptData.localizedDescription ==
            "Error while encrypting data."
        )
        #expect(
            SecureStoreError.cantDecryptData.localizedDescription ==
            "Error while decrypting data."
        )
        #expect(
            SecureStoreError.biometricsCancelled.localizedDescription ==
            "User or system cancelled the biometric prompt."
        )
        #expect(
            SecureStoreError.biometricsFailed.localizedDescription ==
            "Biometric authentication failed after multiple attempts or biometrics are not set up."
        )
        #expect(
            SecureStoreError.cantEncodeData.localizedDescription ==
            "Error while encoding data."
        )
        #expect(
            SecureStoreError.cantDecodeData.localizedDescription ==
            "Error while decoding data."
        )
        #expect(
            SecureStoreError.cantFormatData.localizedDescription ==
            "Error while formatting data."
        )
        
        #expect(
            SecureStoreError.biometricsFailed.localizedDescription ==
            "Biometric authentication failed after multiple attempts or biometrics are not set up."
        )
        #expect(
            SecureStoreError.biometricsCancelled.localizedDescription ==
            "User or system cancelled the biometric prompt."
        )
        #expect(
            SecureStoreError.userFallback.localizedDescription ==
            #"The user tapped the "Fallback" button."#
        )
        #expect(
            SecureStoreError.passcodeNotSet.localizedDescription ==
            "A passcode is not set on the device."
        )
        #expect(
            SecureStoreError.biometryNotAvailable.localizedDescription ==
            "Biometry is not available on the device."
        )
        #expect(
            SecureStoreError.biometryNotEnrolled.localizedDescription ==
            "The user has no enrolled biometric identities."
        )
        #expect(
            SecureStoreError.biometryLockout.localizedDescription ==
            "Too many failed biometry attempts have locked the feature."
        )
        
        #expect(
            SecureStoreError.invalidContext.localizedDescription ==
            "The authentication context is invalid."
        )
        #expect(
            SecureStoreError.notInteractive.localizedDescription ==
            "Displaying the authentication user interface is forbidden."
        )
        #expect(
            SecureStoreError.viewServiceIntialisationFailure.localizedDescription ==
            "The view service failed to initialise."
        )
        #expect(
            SecureStoreError.serviceConnectionInvalidated.localizedDescription ==
            "The service connection was invalidated."
        )
        #expect(
            SecureStoreError.cantDecryptData.localizedDescription ==
            "Error while decrypting data."
        )
        #expect(
            SecureStoreError.defaultDecryptionError.localizedDescription ==
            "Default error for cannot decrypt data. Used when there was no error passed."
        )
    }
    // swiftlint:enable type_body_length
    
    @Test
    func defaultrror() {
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: nil,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.defaultDecryptionError
        )
    }
    
    @Test
    func biometricsFailedError() {
        let authFailedError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.authenticationFailed.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: authFailedError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometricsFailed
        )
    }
    
    @Test
    func biometricsCancelledErrors() {
        let userCancelError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.userCancel.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: userCancelError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometricsCancelled
        )
        
        let systemCancelledError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.systemCancel.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: systemCancelledError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometricsCancelled
        )
        
        let appCancelledError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.appCancel.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: appCancelledError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometricsCancelled
        )
    }
    
    @Test
    func userFallbackError() {
        let userFallbackError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.userFallback.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: userFallbackError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.userFallback
        )
    }
    
    @Test
    func passcodeNotSetError() {
        let passcodeNotSetError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.passcodeNotSet.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: passcodeNotSetError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.passcodeNotSet
        )
    }
    
    @Test
    func biometryNotAvailableError() {
        let biometryNotAvailableError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.biometryNotAvailable.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: biometryNotAvailableError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometryNotAvailable
        )
    }
    
    @Test
    func biometryNotEnrolledError() {
        let biometryNotEnrolledError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.biometryNotEnrolled.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: biometryNotEnrolledError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometryNotEnrolled
        )
    }
    
    @Test
    func biometryLockoutError() {
        let biometryLockoutError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.biometryLockout.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: biometryLockoutError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.biometryLockout
        )
    }
    
    @Test
    func invalidContextError() {
        let invalidContextError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.invalidContext.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: invalidContextError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.invalidContext
        )
    }
    
    @Test
    func notInteractiveError() {
        let notInteractiveError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            LAError.Code.notInteractive.rawValue,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: notInteractiveError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.notInteractive
        )
    }
    
    @Test
    func viewServiceIntialisationFailureError() {
        let viewServiceIntialisationFailureError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            6,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: viewServiceIntialisationFailureError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.viewServiceIntialisationFailure
        )
    }
    
    @Test
    func serviceConnectionInvalidatedError() {
        let serviceConnectionInvalidatedError = CFErrorCreate(
            nil,
            LAErrorDomain as CFString,
            -1000,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: serviceConnectionInvalidatedError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.serviceConnectionInvalidated
        )
    }
    
    @Test
    func cantDecryptDataError() {
        let cantDecryptDataError = CFErrorCreate(
            nil,
            NSOSStatusErrorDomain as CFString,
            -50,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: cantDecryptDataError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? SecureStoreError ==
            SecureStoreError.cantDecryptData
        )
    }
    
    @Test
    func uncaughtError() {
        let uncaughtError = CFErrorCreate(
            nil,
            "test domain" as CFString,
            123456789,
            nil
        )
        #expect(
            SecureStoreError.biometricErrorHandling(
                error: uncaughtError,
                defaultError: SecureStoreError.defaultDecryptionError
            ) as? NSError ==
            uncaughtError as? NSError
        )
    }
}
// swiftlint:enable type_body_length
