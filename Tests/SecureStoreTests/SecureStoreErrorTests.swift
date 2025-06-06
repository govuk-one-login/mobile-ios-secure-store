@testable import SecureStore
import XCTest

final class SecureStoreErrorTests: XCTestCase {
    func test_descriptions() {
        XCTAssertEqual(SecureStoreError.unableToRetrieveFromUserDefaults.localizedDescription, "Error while retrieving item from User Defaults")
        XCTAssertEqual(SecureStoreError.cantGetPublicKeyFromPrivateKey.localizedDescription, "Error while getting public key from private key")
        XCTAssertEqual(SecureStoreError.cantDeleteKey.localizedDescription, "Error while deleting key from the keychain")
        XCTAssertEqual(SecureStoreError.cantStoreKey.localizedDescription, "Error while storing key to the keychain")
        XCTAssertEqual(SecureStoreError.cantRetrieveKey.localizedDescription, "Error while retrieving key from the keychain")
        XCTAssertEqual(SecureStoreError.cantEncryptData.localizedDescription, "Error while encrypting data")
        XCTAssertEqual(SecureStoreError.cantDecryptData.localizedDescription, "Error while decrypting data")
        XCTAssertEqual(SecureStoreError.biometricsCancelled.localizedDescription, "User or system cancelled the biometric prompt")
        XCTAssertEqual(SecureStoreError.biometricsFailed.localizedDescription, "Biometric authentication failed after multiple attempts or biometrics are not set up")
        XCTAssertEqual(SecureStoreError.cantEncodeData.localizedDescription, "Error while encoding data")
        XCTAssertEqual(SecureStoreError.cantDecodeData.localizedDescription, "Error while decoding data")
        XCTAssertEqual(SecureStoreError.cantFormatData.localizedDescription, "Error while formatting data")
    }
    
    func test_biometricErrors() {
        let authFailedError = CFErrorCreate(nil, "domain" as CFString, -1, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(error: authFailedError, defaultError: SecureStoreError.cantEncryptData) as? SecureStoreError,
                       SecureStoreError.biometricsFailed)
        XCTAssertNotEqual(SecureStoreError.biometricErrorHandling(error: authFailedError, defaultError: SecureStoreError.cantEncryptData) as? SecureStoreError,
                          SecureStoreError.biometricsCancelled)
        let userCancelError = CFErrorCreate(nil, "domain" as CFString, -2, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(error: userCancelError, defaultError: SecureStoreError.cantEncryptData) as? SecureStoreError,
                       SecureStoreError.biometricsCancelled)
        let systemCancelError = CFErrorCreate(nil, "domain" as CFString, -4, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(error: systemCancelError, defaultError: SecureStoreError.cantEncryptData) as? SecureStoreError,
                       SecureStoreError.biometricsCancelled)
    }
}
