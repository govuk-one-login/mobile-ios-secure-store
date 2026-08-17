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
    
    @Test("""
            GIVEN a new `KeyManagerService` over time
            AND a call to `KeyManagerService.deleteKeys()`
            WHEN querying for the number of keys under the `id` tag
            THEN no keys should be found.
    """)
    func deleteKeysDoesNotAccumulateKeysOverTime() async throws {
        
        let count = 10

        let configuration = SecureStorageConfiguration(
            id: testRunID.uuidString,
            accessControlLevel: .open
        )
        let idTag = Data(configuration.id.utf8)

        for _ in 1...count {
            let sut = KeyManagerService(configuration: configuration)
            try sut.deleteKeys()
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: idTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        #expect(status == errSecItemNotFound)
        #expect(result == nil)
    }

    @Test("There should only be 1 private key generated")
    func checkNumberofGeneratedKeysIsOne() async throws {
        let configuration = SecureStorageConfiguration(
            id: testRunID.uuidString,
            accessControlLevel: .open
        )
        let idTag = Data(configuration.id.utf8)

        _ = KeyManagerService(configuration: configuration)

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: idTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let keys = try #require(result as? [SecKey])

        #expect(status == errSecSuccess)
        #expect(keys.count == 1)
    }

    /// This is a case where a "leftover" key is under the `id` tag that was not deleted [1].
    /// A new `KeyManagerService` (4.2.0) instance is created which creates a second key under the `id` tag.
    ///
    /// The data is encrypted using the key under the `idPrivateKey` tag.
    ///
    /// The One Login app is updated with an instance of `KeyManagerService` that randomly returns a key under the
    /// `id` tag. e.g. in case of 2 keys, that means there is a 50% chance of returning the wrong key.
    ///
    /// The code attempts to decrypt the data with the public key of the "wrong" key, which trows a
    /// ``SecureStoreError(.cantDecyptData)`` error.
    ///
    /// [1] : See https://govukverify.atlassian.net/browse/DCMAW-22075
    /// - SeeAlso: ``KeyManagerService4_2/make(configuration:)`` which creates the conditions for this test.
    /// - Note: This test reproduces the defect reported at https://govukverify.atlassian.net/browse/DCMAW-22010
    @Test("""
        ON THE CONDITION a leftover key under the `id` tag that was not deleted sometimed in the past
        AND a new `KeyManagerService` (4.2.0) instance is created
        AND any data is encrypted
        GIVEN a new `KeyManagerService` instance is created
        AND a subsequent attempt is made to decrypt the data
        THEN the data is decrypted succesfully
        AND a SecureStoreError(.cantDecryptData) error is NOT thrown
    """)
    func decryptDataPreviouslyEncryptedWithKeyManagerService4_2Succeeds() async throws {
        let configuration = SecureStorageConfiguration(
            id: UUID().uuidString,
            accessControlLevel: .open
        )

        do {
            let keyManagerService4_2 = try KeyManagerService4_2.make(configuration: configuration)

            let encryptedData = try keyManagerService4_2.encryptDataWithPublicKey(dataToEncrypt: "any")

            let sut = KeyManagerService(
                configuration: configuration
            )

            let decrypted = try sut.decryptDataWithPrivateKey(dataToDecrypt: encryptedData)

            #expect(decrypted == "any")
        } catch let error as SecureStoreError where error.kind == .cantDecryptData {
            Issue.record(error)
        } catch let error as KeyManagerService4_2.SecError {
            Issue.record(error)
        }
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
    
    @Test("""
            GIVEN stored key is not available (e.g. deleted)
            WHEN retrieveKeys
            THEN throws SecureStoreError with an original OSStatus error (e.g. OSStatus == errSecItemNotFound)
    """)
    func retrieveKeysSecureStoreErrorWithOriginalOSStatusError() async throws {
        // Delete stored key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let error = #expect(throws: SecureStoreError.self) {
            try sut.retrieveKeys()
        }
        
        #expect(error?.kind == .cantRetrieveKey)
        
        let originalError = try #require(error?.originalError as? OSStatusError)
        
        #expect(originalError.status == errSecItemNotFound)
    }

    @Test("""
            GIVEN `originalError` IS a SecureStoreError (e.g. SecureStoreError(.cantStoreKey))
            AND **its** `originalError` IS an `OSStatus` error (e.g. errSecInteractionNotAllowed)
            AND stored key is not available (e.g. not present),
            WHEN retrieveKeys is called with the `originalError`
            THEN throws SecureStoreError with an original `OSStatus` error (e.g. OSStatus == errSecItemNotFound)
            AND the `underlyingError` is the expected `originalError`
            AND **its** `originalError` is the expected `OSStatusError`
    """)
    func retrieveKeysSecureStoreErrorWithOriginalOSStatusErrorAndUnderlyingError() async throws {
        // Delete stored key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let originalErrorStatus: OSStatus = errSecItemNotFound
        let initError = SecureStoreError(.cantStoreKey, originalError: OSStatusError.make(status: originalErrorStatus))
        
        let error = #expect(throws: SecureStoreError.self) {
            try sut.retrieveKeys(initError: initError)
        }
        
        #expect(error?.kind == .cantRetrieveKey)
        
        let originalError = try #require(error?.originalError as? OSStatusError)
        #expect(originalError.status == errSecItemNotFound)
        
        let underlyingError = try #require(originalError.errorUserInfo[NSUnderlyingErrorKey] as? SecureStoreError)
        #expect(underlyingError.kind == initError.kind)

        let actual = try #require(underlyingError.originalError as? OSStatusError)
        #expect(actual.status == originalErrorStatus)
    }
}
