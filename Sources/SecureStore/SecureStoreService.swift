import Foundation
import LocalAuthentication

public enum SecureStoreError: Error {
    case unableToRetrieveFromUserDefaults
    case cantGetPublicKeyFromPrivateKey
    case cantStoreKey
    case cantRetrieveKey
    case cantEncryptData
    case cantDecryptData
}

public struct SecureStorageConfiguration {
    // What do we use this ID for? Should it be this rather than the key being passed in?
    let id: String
    let accessControlLevel: AccessControlLevel
    
    public init(id: String, accessControlLevel: AccessControlLevel) {
        self.id = id
        self.accessControlLevel = accessControlLevel
    }
    
    public enum AccessControlLevel {
        case `open`
        case anyBiometricsOrPasscode
        case currentBiometricsOnly
        
        var flags: SecAccessControlCreateFlags {
            switch self {
            case .open:
                []
            case .anyBiometricsOrPasscode:
                //private key usage here too?
                [.privateKeyUsage, .biometryAny, .touchIDAny]
            case .currentBiometricsOnly:
                [.privateKeyUsage, .biometryCurrentSet]
            }
        }
    }
}

public struct SecureStoreService {
    private let userDefaults = UserDefaults.standard
    private let configuration: SecureStorageConfiguration

    public init(configuration: SecureStorageConfiguration) {
        self.configuration = configuration
    }
}

// MARK: Interaction with UserDefaults
extension SecureStoreService {
    // Saves the encrypted string to userdefaults for retrieval later
    func saveEncryptedItemToUserDefaults(encyptedItem: String, keyToSaveAs: String) throws {
        do {
            userDefaults.set(encyptedItem, forKey: keyToSaveAs)
        } catch {
            throw SecureStoreError.unableToRetrieveFromUserDefaults
        }
    }
    
    // Retrives the encrypted string from userdefaults
    func retrieveEncryptedItemFromUserDefaults(keySavedAs: String) throws -> String? {
        do {
            return userDefaults.string(forKey: keySavedAs)
        } catch {
            throw SecureStoreError.unableToRetrieveFromUserDefaults
        }
    }
}

// MARK: Interaction with SecureEnclave
extension SecureStoreService {
    // Creating a key pair where the public key is stored in the keychain and the private key is stored in the Secure Enclave
    func createKeys(name: String) throws -> (publicKey: SecKey, privateKey: SecKey)? {
        
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, 
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly, 
                                                           configuration.accessControlLevel.flags,
                                                           nil),
              let tag = name.data(using: .utf8) else { return nil }
        
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
        
        return (publicKey: publicKey, privateKey: privateKey)
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
    }
    
    
    // Deletes a given key to the keychain
    func deleteKeys(name: String) throws {
        let tag = name.data(using: .utf8)!
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tag]
        
        let status = SecItemDelete(addquery as CFDictionary)
        guard status == errSecSuccess else {
            throw SecureStoreError.cantStoreKey
        }
    }

    // Retrieve a key that has been stored before
    func retrieveKey(nameOfKey: String) throws -> SecKey? {
        guard let tag = nameOfKey.data(using: .utf8) else { return nil }
        
        // This constructs a query that will be sent to keychain
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        // errSecSuccess is the result code returned when no error where found with the query
        guard status == errSecSuccess else {
            throw SecureStoreError.cantRetrieveKey
        }
        return (item as! SecKey)
    }

}

// MARK: Encryption and Decryption
extension SecureStoreService {
    func encryptDataWithPublicKey(dataToEncrypt: String, publicKeyName: String) throws -> String? {
        guard let publicKey = try retrieveKey(nameOfKey: publicKeyName) else {
            throw SecureStoreError.cantRetrieveKey
        }
        
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw SecureStoreError.cantEncryptData
        }
        
        guard let encryptData = SecKeyCreateEncryptedData(publicKey,
                                                          SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          nil) else {
            throw SecureStoreError.cantEncryptData
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])
                
        return encryptedString
    }


    func decryptDataWithPrivateKey(dataToDecrypt: String, privateKeyRepresentationName: String) throws -> String? {
        guard let privateKeyRepresentation = try retrieveKey(nameOfKey: privateKeyRepresentationName) else {
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
        guard let item = userDefaults.string(forKey: key) else { return false }
        return true
    }
    
    public func readItem(withKey: String) throws -> String? {
        guard let encryptedData = try retrieveEncryptedItemFromUserDefaults(keySavedAs: withKey) else { throw SecureStoreError.unableToRetrieveFromUserDefaults }
        return try decryptDataWithPrivateKey(dataToDecrypt: encryptedData, privateKeyRepresentationName: "\(withKey)PrivateKey")
    }
    
    public func saveItem(item: String, itemName: String) throws {
        do {
            if let keys = try createKeys(name: itemName) {
                try storeKeys(keyToStore: keys.publicKey, name: "\(itemName)PublicKey")
                try storeKeys(keyToStore: keys.privateKey, name: "\(itemName)PrivateKey")
                
                guard let encryptedData = try encryptDataWithPublicKey(dataToEncrypt: item, publicKeyName: "\(itemName)PublicKey") else {
                    return
                }
                
                try saveEncryptedItemToUserDefaults(encyptedItem: encryptedData, keyToSaveAs: itemName)
            }
        } catch {
            throw error
        }
    }
    
    public func deleteItem(keyToDelete: String) throws {
        try deleteKeys(name: "\(keyToDelete)PublicKey")
        try deleteKeys(name: "\(keyToDelete)PrivateKey")
        
        userDefaults.removeObject(forKey: keyToDelete)
    }
}
