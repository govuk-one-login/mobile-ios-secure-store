import Foundation
@testable import SecureStore

/// This implementation aims to replicate the behaviour by the `KeyManagerService` in the 4.2 tag/release.
final class KeyManagerService4_2 {
    
    enum SecError: Error  {
        case secKeyCreateSecureEnclave(attributes: [String: Sendable], tag: String, underlyingError: NSError?)
        case secItemCopyMatching(query: [String: Sendable], underlyingError: Error)
        case unexpectedKeyCount(result: CFTypeRef?)
        
        var failureReason: String? {
            switch self {
            case let .secKeyCreateSecureEnclave(attributes, tag, nil):
                return "SecKeyCreateRandomKey failed to give reason when creating key under tag: \(tag) using atributes: \(attributes)"
            case let .secKeyCreateSecureEnclave(_, _, underlyingError?):
                return underlyingError.localizedFailureReason
            case let .secItemCopyMatching(_, underlyingError):
                return underlyingError.localizedDescription
            case .unexpectedKeyCount:
                return "Unknown reason"
            }
        }
        
        var description: String {
            switch self {
            case let .secKeyCreateSecureEnclave(attributes, tag, nil):
                return "SecKeyCreateRandomKey failed to create key under tag: \(tag) using atributes: \(attributes)"
            case let .secKeyCreateSecureEnclave(attributes, tag, underlyingError?):
                return "SecKeyCreateRandomKey failed to create key under tag: \(tag) using atributes: \(attributes) with underlyingError: \(underlyingError)"
            case let .secItemCopyMatching(query, underlyingError):
                return "SecItemCopyMatching failed to succesfully return a result for the query: \(query) with underlyingError: \(underlyingError)"
            case .unexpectedKeyCount(nil):
                return "Expected more than 1 key."
            case let .unexpectedKeyCount(result?):
                return "Expected more than 1 key. Instead received: \(result)"
            }
        }
    }
    
    /// Creates the conditions that would lead to two keys being present under the same `id` tag.
    ///
    /// * A leftover key under the `id` tag that was not deleted sometimed in the past [1]
    /// * A new `KeyManagerService` (4.2.0) instance is created
    ///     * The `createKeysIfNeeded(name: String)` will create a new set of keys:
    ///         * One under id tag
    ///         * Another under the idPrivateKey tag
    ///
    /// [1]: Previous versions of the `KeyManagerService` accumulates keys over time
    /// - Postcondition: 2 keys will be present under the `id` tag of type managed by the Secure Enclave.
    /// - SeeAlso: https://govukverify.atlassian.net/browse/DCMAW-22075
    static func make(configuration: SecureStorageConfiguration) throws -> KeyManagerService4_2 {
            
        let idTag = Data(configuration.id.utf8)
        
        //  A leftover key under the `id` tag that was not deleted sometimed in the past [1]
        let attributes: [CFString: Sendable] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: idTag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            guard let error = error?.takeRetainedValue() as? NSError else {
                throw SecError.secKeyCreateSecureEnclave(attributes: (attributes as [String : Sendable]), tag: idTag.description, underlyingError: nil)
            }
            throw SecError.secKeyCreateSecureEnclave(attributes: (attributes as [String : Sendable]), tag: idTag.description, underlyingError: error)
        }

        // A new `KeyManagerService` (4.2.0) instance is created
        let keyManagerService = KeyManagerService4_2(configuration: configuration)
        
        // two keys being present under the same `id` tag.
        let query: [String: Sendable] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: idTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw SecError.secItemCopyMatching(query: query, underlyingError: OSStatusError.make(status: status))
        }
        
        guard let keys = result as? [SecKey], keys.count > 1 else {
            throw SecError.unexpectedKeyCount(result: result)
        }

        return keyManagerService
    }
    
    let configuration: SecureStorageConfiguration
    var initError: Error?
    
    init(configuration: SecureStorageConfiguration) {
        self.configuration = configuration
        
        do {
            try createKeysIfNeeded(name: configuration.id)
        } catch {
            self.initError = error
            return
        }
    }
    
    func createKeysIfNeeded(name: String) throws {
        
        // Check if keys already exist in storage
        do {
            _ = try retrieveKeys()
            return
        } catch let error as SecureStoreError where error.kind == .cantRetrieveKey {
            // Keys do not exist yet, continue below to create and save them
        }
        
        #if targetEnvironment(simulator)
        let requirement = SecureStorageConfiguration.AccessControlLevel.open.flags
        #else
        let requirement = configuration.accessControlLevel.flags
        #endif
        
        var accessControlCreateWithFlagsError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           requirement,
                                                           &accessControlCreateWithFlagsError),
              let tag = name.data(using: .utf8) else {
            guard let error = accessControlCreateWithFlagsError?.takeRetainedValue() as? Error else {
                throw SecureStoreError(.noResultOrError)
            }
            throw error
        }
        
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw SecureStoreError(.cantEncryptData)
            }
            throw error
        }
        
        try storePrivateKey(keyToStore: privateKey, name: "\(configuration.id)PrivateKey")
    }
    
    func storePrivateKey(keyToStore: SecKey, name: String) throws {
        let key = keyToStore
        let tag = name.data(using: .utf8)!
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tag,
                                       kSecValueRef as String: key]
        
        // Add item to KeyChain
        let status = SecItemAdd(addquery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureStoreError(.cantStoreKey, originalError: OSStatusError.make(status: status, underlyingError: self.initError))
        }
    }
        
    func retrieveKeys(localAuthStrings: LocalAuthenticationLocalizedStrings? = nil, initError: Error? = nil) throws -> (publicKey: SecKey,
                                                                                               privateKey: SecKey) {
        let privateKeyTag = Data("\(configuration.id)PrivateKey".utf8)
        
        // This constructs a query that will be sent to keychain
        var privateQuery: NSDictionary {
            return [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: privateKeyTag,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef: true
            ]
        }
        
        var privateKeyRef: CFTypeRef?
        let privateStatus = SecItemCopyMatching(privateQuery as CFDictionary, &privateKeyRef)

        // errSecSuccess is the result code returned when no error was found with the query
        guard privateStatus == errSecSuccess else {
            throw SecureStoreError(.cantRetrieveKey, originalError: OSStatusError.make(status: privateStatus))
        }

        // swiftlint:disable force_cast
        let privateKey = privateKeyRef as! SecKey
        // swiftlint:enable force_cast
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureStoreError(.cantRetrieveKey)
        }

        return (publicKey, privateKey)
    }
    
    func deleteKeys() throws {
        let keyType = ["PublicKey", "PrivateKey"]
        try keyType.forEach { key in
            let keyName = configuration.id + key
            let tag = keyName.data(using: .utf8)!
            let deleteQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                           kSecAttrApplicationTag as String: tag]
            
            let status = SecItemDelete(deleteQuery as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw SecureStoreError(.cantDeleteKey, originalError: OSStatusError.make(status: status, underlyingError: self.initError))
            }
        }
    }
}

extension KeyManagerService4_2 {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        let publicKey = try retrieveKeys(initError: self.initError).publicKey
        
        guard let formattedData = dataToEncrypt.data(using: .utf8) else {
            throw SecureStoreError(.cantEncodeData, originalError: self.initError)
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            formattedData as CFData,
            &error
        ) else {
            let nsError = error?.takeRetainedValue() as? NSError
            throw SecureStoreError.biometricErrorHandling(
                error: nsError
            )
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString()
        
        return encryptedString
    }
}
