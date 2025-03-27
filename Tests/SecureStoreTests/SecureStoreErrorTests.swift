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
        XCTAssertEqual(SecureStoreError.cantEncodeOrDecodeData.localizedDescription, "Error while encoding or decoding data")
    }
}
