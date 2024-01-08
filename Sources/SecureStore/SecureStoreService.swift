import Foundation
import LocalAuthentication

public struct SecureStoreService {
    private let secureStoreDefaults: SecureStoreDefaults
    private let configuration: SecureStorageConfiguration
    
    let calledBefore = false

    public init(configuration: SecureStorageConfiguration) {
        self.configuration = configuration
        self.secureStoreDefaults = SecureStoreUserDefaults()
        
        do {
            try createKeysIfNeeded(name: configuration.id)
        } catch {
            print(error)
        }
    }
}

// MARK: Interaction with SecureEnclave
extension SecureStoreService {
    // Creating a key pair where the public key is stored in the keychain and the private key is stored in the Secure Enclave
    func createKeysIfNeeded(name: String) throws {

        // Check if keys already exist in storage
        do {
            try retrieveKeys()
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
            throw error!.takeRetainedValue() as Error
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureStoreError.cantGetPublicKeyFromPrivateKey
        }
        
        try storeKeys(keyToStore: publicKey, name: "\(name)PublicKey")
        try storeKeys(keyToStore: privateKey, name: "\(name)PrivateKey")
    }

    // Store a given key to the keychain in order to reuse it later
    func storeKeys(keyToStore: SecKey, name: String) throws {
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
        
        print("key stored - \(name)")
    }

    // Retrieve a key that has been stored before
    func retrieveKeys() throws -> (publicKey: SecKey, privateKey: SecKey)? {
        guard let privateKeyTag = "\(configuration.id)PrivateKey".data(using: .utf8) else { return nil }
        guard let publicKeyTag = "\(configuration.id)PublicKey".data(using: .utf8) else { return nil }

        // This constructs a query that will be sent to keychain
        let privateQuery: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: privateKeyTag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]
        
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
        
        return (publicKey as! SecKey, privateKey as! SecKey)
    }
}

// MARK: Encryption and Decryption
extension SecureStoreService {
    func encryptDataWithPublicKey(dataToEncrypt: String, publicKeyName: String) throws -> String? {
        guard let publicKey = try retrieveKeys()?.publicKey else {
            throw SecureStoreError.cantRetrieveKey
        }
        
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw SecureStoreError.cantEncryptData
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(publicKey,
                                                          SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])
                
        return encryptedString
    }

    func decryptDataWithPrivateKey(dataToDecrypt: String, privateKeyRepresentationName: String) throws -> String? {
        guard let privateKeyRepresentation = try retrieveKeys()?.privateKey else {
            throw SecureStoreError.cantRetrieveKey
        }
        
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
            print("Error: Cannot convert decrypted data to string")
            return nil
        }
        
        return decryptedString
    }
}

// MARK: Keychain Storable Conformance
extension SecureStoreService: KeychainStorable {
    public func checkItemExists(withKey key: String) throws -> Bool {
        // Implement check key exists - do we want to check user defaults and also secure enclave
        guard let item = try secureStoreDefaults.getItem(withKey: key) else { return false }
        return true
    }
    
    public func readItem(withName name: String) throws -> String? {
        guard let encryptedData = try secureStoreDefaults.retrieveEncryptedItemFromUserDefaults(withKey: name) else { throw SecureStoreError.unableToRetrieveFromUserDefaults }
        return try decryptDataWithPrivateKey(dataToDecrypt: encryptedData, privateKeyRepresentationName: "\(configuration.id)PrivateKey")
    }
    
    public func saveItem(item: String, itemName: String) throws {
        do {
            if let keys = try retrieveKeys() {
                
                guard let encryptedData = try encryptDataWithPublicKey(dataToEncrypt: item, publicKeyName: "\(configuration.id)PublicKey") else {
                    return
                }
                
                try secureStoreDefaults.saveEncryptedItemToUserDefaults(encyptedItem: encryptedData, withKey: itemName)
            }
        } catch {
            throw error
        }
    }
    
    public func deleteItem(keyToDelete: String) throws {
        try secureStoreDefaults.deleteItem(withKey: keyToDelete)
    }
}
