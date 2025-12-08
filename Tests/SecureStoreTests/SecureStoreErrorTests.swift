import LocalAuthentication
@testable import SecureStore
import XCTest

final class SecureStoreErrorTests: XCTestCase {
    func test_descriptions() {
        XCTAssertEqual(SecureStoreError(.unableToRetrieveFromUserDefaults).reason,
                       "Error while retrieving item from User Defaults")
        XCTAssertEqual(SecureStoreError(.cantGetPublicKeyFromPrivateKey).reason,
                       "Error while getting public key from private key")
        XCTAssertEqual(SecureStoreError(.cantDeleteKey).reason,
                       "Error while deleting key from the keychain")
        XCTAssertEqual(SecureStoreError(.cantStoreKey).reason,
                       "Error while storing key to the keychain")
        XCTAssertEqual(SecureStoreError(.cantRetrieveKey).reason,
                       "Error while retrieving key from the keychain")
        XCTAssertEqual(SecureStoreError(.cantEncryptData).reason,
                       "Error while encrypting data")
        XCTAssertEqual(SecureStoreError(.cantDecryptData).reason,
                       "Error while decrypting data")
        XCTAssertEqual(SecureStoreError(.biometricsCancelled).reason,
                       "User or system cancelled the biometric prompt")
        XCTAssertEqual(SecureStoreError(.biometricsFailed).reason,
                       "Biometric authentication failed after multiple attempts or biometrics are not set up")
        XCTAssertEqual(SecureStoreError(.cantEncodeData).reason,
                       "Error while encoding data")
        XCTAssertEqual(SecureStoreError(.cantDecodeData).reason,
                       "Error while decoding data")
        XCTAssertEqual(SecureStoreError(.cantFormatData).reason,
                       "Error while formatting data")
    }
    
    func test_biometricErrors() {
        let userCancelError = CFErrorCreate(nil, LAErrorDomain as CFString, -2, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: userCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
        
        let systemCancelError = CFErrorCreate(nil, LAErrorDomain as CFString, -4, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: systemCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
        
        let notInterativeError = CFErrorCreate(nil, LAErrorDomain as CFString, LAError.notInteractive.rawValue, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: notInterativeError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
        
        let userFallbackError = CFErrorCreate(nil, LAErrorDomain as CFString, LAError.userFallback.rawValue, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: userFallbackError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
        
        let authFailedError = CFErrorCreate(nil, LAErrorDomain as CFString, -1, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: authFailedError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
        
        let backgroundError = CFErrorCreate(nil, LAErrorDomain as CFString, 6, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: backgroundError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
        
        let uiError = CFErrorCreate(nil, LAErrorDomain as CFString, -1000, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: uiError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.biometricsCancelled)
        )
    }
}
