import Foundation
import LocalAuthentication

public struct SecureStoreService {
    let secureStoreDefaults: SecureStoreDefaults
    private let configuration: SecureStorageConfiguration
    
    public init(configuration: SecureStorageConfiguration, secureStoreDefaults: SecureStoreDefaults? = nil) {
        self.configuration = configuration
        self.secureStoreDefaults = secureStoreDefaults ?? SecureStoreUserDefaults()
        
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
    public func createKeysIfNeeded(name: String) throws {
        
        // Check if keys already exist in storage
        do {
            let _ = try retrieveKeys()
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
        
        print("\(name)PublicKey")
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
    public func retrieveKeys() throws -> (publicKey: SecKey, privateKey: SecKey) {
        guard let privateKeyTag = "\(configuration.id)PrivateKey".data(using: .utf8) else { throw SecureStoreError.cantInitialiseData }
        guard let publicKeyTag = "\(configuration.id)PublicKey".data(using: .utf8) else { throw SecureStoreError.cantInitialiseData }
        
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
    
    func decryptDataWithPrivateKey(dataToDecrypt: String, privateKeyRepresentationName: String) throws -> String? {
        let privateKeyRepresentation = try retrieveKeys().privateKey
        
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
extension SecureStoreService: SecureStorable {
    public func checkItemExists(itemName: String) throws -> Bool {
        // Implement check key exists - do we want to check user defaults and also secure enclave
        guard let _ = try secureStoreDefaults.getItem(itemName: itemName) else { return false }
        return true
    }
    
    public func readItem(itemName: String) throws -> String? {
        guard let encryptedData = try secureStoreDefaults.getItem(itemName: itemName) else { throw SecureStoreError.unableToRetrieveFromUserDefaults }
        return try decryptDataWithPrivateKey(dataToDecrypt: encryptedData, privateKeyRepresentationName: "\(configuration.id)PrivateKey")
    }
    
    public func saveItem(item: String, itemName: String) throws {
        do {
            let _ = try retrieveKeys()
            
            guard let encryptedData = try encryptDataWithPublicKey(dataToEncrypt: item, publicKeyName: "\(configuration.id)PublicKey") else {
                return
            }
            
            try secureStoreDefaults.saveItem(encyptedItem: encryptedData, itemName: itemName)
        } catch {
            throw error
        }
    }
    
    public func deleteItem(itemName: String) throws {
        try secureStoreDefaults.deleteItem(itemName: itemName)
    }
    
    public func delete() throws {
        try deleteKeys(name: "\(configuration.id)PrivateKey")
        try deleteKeys(name: "\(configuration.id)PublicKey")
    }
}
