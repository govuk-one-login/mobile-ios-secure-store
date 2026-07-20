import Foundation
import LocalAuthentication
@testable import SecureStore
import Testing

@Suite
struct KeyManagerServiceTests: ~Copyable {
    private let testRunID = UUID()
    private let sut: KeyManagerService

    private var keyTag: Data {
        Data("\(testRunID)".utf8)
    }

    init() {
        sut = KeyManagerService(configuration: .init(
            id: testRunID.uuidString,
            accessControlLevel: .open
        ))
    }

    deinit {
        try? sut.deleteKeys()
    }

    @Test("When initialised, KeyManagerService creates private key and stores this in keychain")
    func createsKeyOnInitialisation() async throws {

        let query = NSDictionary(dictionary: [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ])

        var privateKeyRef: CFTypeRef?
        let privateStatus = SecItemCopyMatching(query as CFDictionary, &privateKeyRef)

        #expect(privateStatus == errSecSuccess)
    }

    @Test("When retrieving keys, KeyManagerService generates this from the stored private key")
    func generatesPublicKeyOnDemand() async throws {
        // Override stored key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrApplicationTag: keyTag
            ]
        ]
        let privateKey = try #require(SecKeyCreateRandomKey(addQuery, nil))

        // Ensure that the public key matches the new stored key
        let keys = try sut.retrieveKeys()
        #expect(keys.privateKey == privateKey)

        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        #expect(keys.publicKey == publicKey)
    }

    /// This is a case where a as part of instantiating a `KeyManagerService`, a new set of keys is created
    /// that is tied to the Secure Enclave (i.e. `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`).
    ///
    /// The keys are explicitly deleted by calling `deleteKeys()` in the  `KeyManagerService`
    ///
    /// When attempting to **decrypt** the data, an `errSecParam` (aka -50) will be thrown
    @Test("""
            GIVEN a new `KeyManagerService` with a set of keys
            AND a data is encrypted
            AND the keys are explicitly deleted
            AND a new `KeyManagerService` is created with the same (i.e. same `id`) configuration
            WHEN attempting to decrypt the data
            THEN throws `SecureStoreError.cantDecryptData`
            AND the `originalError` is `errSecParam` (i.e. -50 OSStatus)
    """)
    func decryptKeyWithWrongPrivateKey() async throws {

        let anyString = "any"
        let encrypted = try sut.encryptDataWithPublicKey(dataToEncrypt: anyString)
                
        try sut.deleteKeys()

        let sut = KeyManagerService(configuration: .init(
            id: testRunID.uuidString,
            accessControlLevel: .open
        ))

        let error = #expect(throws: SecureStoreError.self) {
            try sut.decryptDataWithPrivateKey(dataToDecrypt: encrypted)
        }
        
        #expect(error?.kind == .cantDecryptData)
        
        let originalError = try #require(error?.originalError as? NSError)
        #expect(originalError.code == errSecParam)
        #expect(originalError.code == -50)
    }
    
    /// This is a case where a as part of instantiating a `KeyManagerService`, a new set of keys is created
    /// that is tied to the Secure Enclave (i.e. `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`).
    ///
    /// A SE key pair provides strong guarantees so that:
    /// * It is never exported to a backup
    /// * The key pair is deleted as soon as the device is erased
    ///
    /// In this case:
    /// 1. a backup from an existing device, with previously encrypted data, was taken
    /// 2. a restore on the device is performed
    /// 3. the data is restored
    /// 4. the key is not restored
    ///
    /// When attempting to **decrypt** the data, an `errSecParam` (aka -50) will be thrown
    @Test("""
            GIVEN a new `KeyManagerService` with a set of keys
            AND a data is encrypted
            AND the key is deleted due (e.g. due to a device erase)
            AND a new `KeyManagerService` is created with the same (i.e. same `id`) configuration as part of a new app installation
            WHEN attempting to decrypt the existing, previously backed-up, data
            THEN throws `SecureStoreError.cantDecryptData`
            AND the `originalError` is `errSecParam` (i.e. -50 OSStatus)
    """)
    func decryptKeyWithWrongPrivateKeyDueToOriginalKeyGoneMising() async throws {

        let anyString = "any"
        let encrypted = try sut.encryptDataWithPublicKey(dataToEncrypt: anyString)
        
        // Device Erased
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // New app installation
        let sut = KeyManagerService(configuration: .init(
            id: testRunID.uuidString,
            accessControlLevel: .open
        ))

        let error = #expect(throws: SecureStoreError.self) {
            try sut.decryptDataWithPrivateKey(dataToDecrypt: encrypted)
        }
        
        #expect(error?.kind == .cantDecryptData)
        
        let originalError = try #require(error?.originalError as? NSError)
        #expect(originalError.code == errSecParam)
        #expect(originalError.code == -50)
    }
}
