import Foundation
import LocalAuthentication

class KeyManagerService {
    let defaultsStore: DefaultsStore
    private let configuration: SecureStorageConfiguration

    public convenience init(configuration: SecureStorageConfiguration) {
        self.init(configuration: configuration, defaultsStore: UserDefaultsStore())
    }

    init(configuration: SecureStorageConfiguration, defaultsStore: DefaultsStore) {
        self.configuration = configuration
        self.defaultsStore = defaultsStore

        do {
            try createKeysIfNeeded(name: configuration.id)
        } catch {
            return
        }
    }
}

// MARK: Interaction with SecureEnclave
extension KeyManagerService {
    // Creating a key pair where the public key is stored in the keychain
    // and the private key is stored in the Secure Enclave
    public func createKeysIfNeeded(name: String) throws {

        // Check if keys already exist in storage
        do {
            _ = try retrieveKeys()
            return
        } catch let error as SecureStoreError where error == .cantRetrieveKey {
            // Keys do not exist yet, continue below to create and save them
        }

        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           configuration.accessControlLevel.flags,
                                                           nil),
        let tag = name.data(using: .utf8) else { return }

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
                throw SecureStoreError.cantEncryptData
            }
            throw error
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureStoreError.cantGetPublicKeyFromPrivateKey
        }

        try storeKeys(keyToStore: publicKey, name: "\(name)PublicKey")
        try storeKeys(keyToStore: privateKey, name: "\(name)PrivateKey")
    }

    // Store a given key to the keychain in order to reuse it later
    public func storeKeys(keyToStore: SecKey, name: String) throws {
        let key = keyToStore
        let tag = name.data(using: .utf8)!
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tag,
                                       kSecValueRef as String: key]

        // Add item to KeyChain
        let status = SecItemAdd(addquery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureStoreError.cantStoreKey
        }
    }

    // Deletes a given key to the keychain
    public func deleteKeys(name: String) throws {
        let tag = name.data(using: .utf8)!
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tag]

        let status = SecItemDelete(addquery as CFDictionary)
        guard status == errSecSuccess else {
            throw SecureStoreError.cantStoreKey
        }
    }

    // Retrieve a key that has been stored before
    public func retrieveKeys(localAuthStrings: LocalAuthenticationLocalizedStrings? = nil) throws -> (publicKey: SecKey,
                                                                                   privateKey: SecKey) {
        guard let privateKeyTag = "\(configuration.id)PrivateKey".data(using: .utf8) else {
            throw SecureStoreError.cantInitialiseData
        }
        guard let publicKeyTag = "\(configuration.id)PublicKey".data(using: .utf8) else {
            throw SecureStoreError.cantInitialiseData
        }
        
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
        
        var privateKey: CFTypeRef?
        let privateStatus = SecItemCopyMatching(privateQuery as CFDictionary, &privateKey)

        // errSecSuccess is the result code returned when no error where found with the query
        guard privateStatus == errSecSuccess else {
            throw SecureStoreError.cantRetrieveKey
        }

        // This constructs a query that will be sent to keychain
        let publicQuery: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: publicKeyTag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]

        var publicKey: CFTypeRef?
        let publicStatus = SecItemCopyMatching(publicQuery as CFDictionary, &publicKey)

        // errSecSuccess is the result code returned when no error where found with the query
        guard publicStatus == errSecSuccess else {
            throw SecureStoreError.cantRetrieveKey
        }

        // swiftlint:disable force_cast
        return (publicKey as! SecKey, privateKey as! SecKey)
        // swiftlint:enable force_cast
    }
}

// MARK: Encryption and Decryption
extension KeyManagerService {
    public func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String? {
        let publicKey = try retrieveKeys().publicKey

        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw SecureStoreError.cantEncryptData
        }

        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(publicKey,
                                                          SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw SecureStoreError.cantEncryptData
            }
            throw error
        }

        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])

        return encryptedString
    }

    public func decryptDataWithPrivateKey(dataToDecrypt: String,
                                          localAuthStrings: LocalAuthenticationLocalizedStrings?) throws -> String? {
        let privateKeyRepresentation = try retrieveKeys(localAuthStrings: configuration.localAuthStrings).privateKey

        guard let formattedData = Data(base64Encoded: dataToDecrypt, options: [])  else {
            throw SecureStoreError.cantDecryptData
        }

        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        guard let decryptData = SecKeyCreateDecryptedData(privateKeyRepresentation,
                                                          SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          nil) else {
            throw SecureStoreError.cantDecryptData
        }

        guard let decryptedString = String(data: decryptData as Data, encoding: String.Encoding.utf8) else {
            throw SecureStoreError.cantDecryptData
        }

        return decryptedString
    }
}
