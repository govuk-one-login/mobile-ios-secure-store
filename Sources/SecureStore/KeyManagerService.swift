import Foundation
import LocalAuthentication

final class KeyManagerService {
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
}

// MARK: Interaction with SecureEnclave
extension KeyManagerService {
    // Creating a key pair where the public key is stored in the keychain
    // and the private key is stored in the Secure Enclave
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

        try storePrivateKey(keyToStore: privateKey, name: "\(name)PrivateKey")
    }
    
    // Store a given key to the keychain in order to reuse it later
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
    
    // Deletes a given key to the keychain
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
    
    /// Retrieve the key stored under ``SecureStorageConfiguration/id``+"PrivateKey".
    ///
    /// - Parameters:
    ///     - localAuthStrings: optional; in case your code expects the user to be prompted and need to provide a
    ///         `localizedReason`,   `localizedFallbackTitle` and `localizedCancelTitle`; default `nil`
    ///     - initError: optional, in case your code needs to also record the underlying error raised when this
    ///         ``KeyManagerService`` was ``init( configuration:)``,  pass the error (i.e. ``self.initError``)
    /// - throws: ``SecureStoreError(.cantRetrieveKey)`` in case either the private or its corresponding public key cannot be retrieved;
    ///     the "root underlying error" error holds the value of the error passed in as `initError`
    func retrieveKeys(localAuthStrings: LocalAuthenticationLocalizedStrings? = nil, initError: Error? = nil) throws -> (publicKey: SecKey,
                                                                                               privateKey: SecKey) {
        let privateKeyTag = Data("\(configuration.id)PrivateKey".utf8)
        // This constructs a query that will be sent to keychain
        var privateQuery: NSDictionary {
            let context = LAContext()
            
            if let localAuthStrings {
                // Local Authentication prompt strings
                context.localizedReason = localAuthStrings.localizedReason
                context.localizedFallbackTitle = localAuthStrings.localisedFallbackTitle
                context.localizedCancelTitle = localAuthStrings.localisedCancelTitle
            }
            return [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: privateKeyTag,
                kSecUseAuthenticationContext as String: context,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef: true
            ]
        }
        
        var privateKeyRef: CFTypeRef?
        let privateStatus = SecItemCopyMatching(privateQuery as CFDictionary, &privateKeyRef)

        // errSecSuccess is the result code returned when no error was found with the query
        guard privateStatus == errSecSuccess else {
            throw SecureStoreError(.cantRetrieveKey, originalError: OSStatusError.make(status: privateStatus, underlyingError: initError))
        }

        // swiftlint:disable force_cast
        let privateKey = privateKeyRef as! SecKey
        // swiftlint:enable force_cast
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureStoreError(.cantRetrieveKey, originalError: initError)
        }

        return (publicKey, privateKey)
    }

    /// Returns an ``Encryptor`` that can be used to encrypt data using the underlying instance of
    /// ``KeyManagerService``.
    ///
    /// Use an encryptor when you want to handle a  ``SecureStoreError(.cantRetrieveKey)`` independently
    /// from any ``SecureStoreError`` thrown by ``encryptDataWithPublicKey(datatoEncrypt:publicKey)``
    ///
    /// Effectively, this allows for a two step apprach to encryption.
    /// 1. Ensure that the public key is accessible
    /// 2. Encrypt the data with that public key
    ///
    /// This enables you to decide the right moment and place in your code to retrieve the public key, independently
    /// of when you have to encrypt the data.
    ///
    /// - throws: ``SecureStoreError(.cantRetrieveKey)`` in case either the private or its corresponding public key cannot be retrieved;
    ///     the "root underlying error" error holds the value of the error passed in as `initError`
    func encryptor() throws -> Encryptor {
        let publicKey = try retrieveKeys(initError: initError).publicKey

        return Encryption(publicKey: publicKey) { value, publicKey in
            try self.encrypt(
                value: value,
                using: publicKey
            )
        }
    }
    
    /// Encrypts the given value; optionally passing a public key.
    ///
    /// - Parameters:
    ///     - value: the value to encrypt. The given String must be able to be encoded in utf8.
    ///     - publicKey: the public key to use to encrypt the data.
    /// - throws: ``SecureStoreError(.cantEncodeData)`` in case the given String cannot be encoding
    ///     in utf8.
    /// - SeeAlso: ``SecureStoreError/biometricErrorHandling(error)`` for any errors thrown attempting to encrypt.
    ///
    /// - SeeAlso: ``Encryptor`` if you need a two step approach to encryption.
    private func encrypt(value: String, using publicKey: SecKey) throws -> String {
        guard let formattedData = value.data(using: .utf8) else {
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

/// An encryptor allows you to encrypt a value (i.e. a `String`)
///
/// - SeeAlso: ``KeyManagerService/encryptor`` on how to obtain an instance
public protocol Encryptor {
    func encrypt(value: String) throws -> String
}

private struct Encryption: Encryptor {
    typealias EncryptAsFunction = (_ value: String, _ publicKey: SecKey) throws -> String
    
    private let publicKey: SecKey
    private let encryptAsFunction: EncryptAsFunction

    init(publicKey: SecKey, _ encryptAsFunction: @escaping EncryptAsFunction) {
        self.publicKey = publicKey
        self.encryptAsFunction = encryptAsFunction
    }

    public func encrypt(value: String) throws -> String {
        return try encryptAsFunction(value, publicKey)
    }
}

// MARK: Encryption and Decryption
extension KeyManagerService {
    
    /// Encrypts the given data; using the public key as managed by this ``KeyManagerService``  instance.
    ///
    /// - Parameters:
    ///     - dataToEncrypt: the data to encrypt. The given String must be able to be encoded in utf8.
    /// - throws: ``SecureStoreError(.cantRetrieveKey)`` in case the key has to be retrieved.
    /// - throws: ``SecureStoreError(.cantEncodeData)`` in case the given String cannot be encoding
    ///     in utf8.
    /// - SeeAlso: ``SecureStoreError/biometricErrorHandling(error)`` for any errors thrown attempting to encrypt.
    /// 
    /// - SeeAlso: ``Encryptor`` if you need a two step approach to encryption.
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        let publicKey = try retrieveKeys(initError: self.initError).publicKey
        return try self.encrypt(value: dataToEncrypt, using: publicKey)
    }
    
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws(SecureStoreError) -> String {
        let privateKeyRepresentation: SecKey
        do {
            privateKeyRepresentation = try retrieveKeys(
                localAuthStrings: configuration.localAuthStrings,
                initError: self.initError
            ).privateKey
        } catch {
            throw SecureStoreError(
                .cantRetrieveKey,
                reason: error.localizedDescription,
                originalError: error
            )
        }
        
        guard let formattedData = Data(base64Encoded: dataToDecrypt)  else {
            throw SecureStoreError(.cantFormatData, originalError: self.initError)
        }
        
        var error: Unmanaged<CFError>?
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        guard let decryptData = SecKeyCreateDecryptedData(
            privateKeyRepresentation,
            .eciesEncryptionStandardX963SHA256AESGCM,
            formattedData as CFData,
            &error
        ) else {
            let nsError = error?.takeRetainedValue() as? NSError
            throw SecureStoreError.biometricErrorHandling(
                error: nsError
            )
        }
        
        guard let decryptedString = String(
            data: decryptData as Data,
            encoding: .utf8
        ) else {
            throw SecureStoreError(.cantDecodeData, originalError: self.initError)
        }
        
        return decryptedString
    }
}
