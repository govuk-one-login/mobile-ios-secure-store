import Foundation
import LocalAuthentication

final class KeyManagerService {
    let configuration: SecureStorageConfiguration
    
    init(configuration: SecureStorageConfiguration) {
        self.configuration = configuration
        try? createKeysIfNeeded()
    }
    
    private lazy var privateKeyIdentifier = { configuration.id + "PrivateKey" }()
    private lazy var publicKeyIdentifier = { configuration.id + "PublicKey" }()
}

// MARK: Interaction with SecureEnclave
extension KeyManagerService {
    // Creating a key pair where the public key is stored in the keychain
    // and the private key is stored in the Secure Enclave
    // swiftlint:disable function_body_length
    func createKeysIfNeeded() throws {
        // Check if keys already exist in storage
        do {
            try retrieveKeys()
            return
        } catch let error as SecureStoreError where error == .cantRetrieveKey {
            // Keys do not exist yet, continue below to create and save them
            debugPrint("SecureStore: CANT RETRIEVE KEYS")
        }
        
        // Delete keys if none were found to avoid errors around multiple keys
        try deleteKeys()
        
        #if targetEnvironment(simulator)
        let requirement = SecureStorageConfiguration.AccessControlLevel.open.flags
        #else
        let requirement = configuration.accessControlLevel.flags
        #endif
        
        var flagError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            requirement,
            &flagError
        ) else {
            guard let error = flagError?.takeRetainedValue() as? Error else {
                throw SecureStoreError.cantEncryptData
            }
            throw error
        }
        
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: Data(configuration.id.utf8),
                kSecAttrAccessControl: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(
            attributes,
            &error
        ) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw SecureStoreError.cantEncryptData
            }
            throw error
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureStoreError.cantGetPublicKeyFromPrivateKey
        }
        
        try storeKeys(
            keyToStore: privateKey,
            name: privateKeyIdentifier
        )
        try storeKeys(
            keyToStore: publicKey,
            name: publicKeyIdentifier
        )
    }
    // swiftlint:enable function_body_length
    
    // Store a given key to the keychain in order to reuse it later
    func storeKeys(
        keyToStore: SecKey,
        name: String
    ) throws {
        let addQuery: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: Data(name.utf8),
            kSecValueRef: keyToStore
        ]
        
        // Add item to KeyChain
        guard SecItemAdd(
            addQuery as CFDictionary,
            nil
        ) == errSecSuccess else {
            throw SecureStoreError.cantStoreKey
        }
    }
    
    // Deletes a given key to the keychain
    func deleteKeys() throws {
        try [
            privateKeyIdentifier,
            publicKeyIdentifier
        ].forEach { key in
            let deleteQuery: NSDictionary = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: Data(key.utf8)
            ]
            
            let status = SecItemDelete(deleteQuery as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw SecureStoreError.cantDeleteKey
            }
        }
    }
    
    // Retrieve a key that has been stored before
    @discardableResult
    func retrieveKeys(
        localAuthStrings: LocalAuthenticationLocalizedStrings? = nil
    ) throws -> (publicKey: SecKey, privateKey: SecKey) {
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
                kSecAttrApplicationTag: Data(privateKeyIdentifier.utf8),
                kSecUseAuthenticationContext: context,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef: true
            ]
        }
        
        // errSecSuccess is the result code returned when no error was found with the query
        var privateKey: CFTypeRef?
        guard SecItemCopyMatching(
            privateQuery as CFDictionary,
            &privateKey
        ) == errSecSuccess else {
            throw SecureStoreError.cantRetrieveKey
        }
        
        // This constructs a query that will be sent to keychain
        let publicQuery: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: Data(publicKeyIdentifier.utf8),
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]
        
        // errSecSuccess is the result code returned when no error was found with the query
        var publicKey: CFTypeRef?
        guard SecItemCopyMatching(
            publicQuery as CFDictionary,
            &publicKey
        ) == errSecSuccess else {
            throw SecureStoreError.cantRetrieveKey
        }
        
        // swiftlint:disable force_cast
        return (publicKey as! SecKey, privateKey as! SecKey)
        // swiftlint:enable force_cast
    }
}

// MARK: Encryption and Decryption
extension KeyManagerService {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        try createKeysIfNeeded()
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(
            try retrieveKeys().publicKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            Data(dataToEncrypt.utf8) as CFData,
            &error
        ) else {
            throw SecureStoreError.biometricErrorHandling(
                error: error?.takeRetainedValue(),
                defaultError: SecureStoreError.cantEncryptData
            )
        }
        
        return (encryptedData as Data).base64EncodedString()
    }
    
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws -> String {
        guard let formattedData = Data(base64Encoded: dataToDecrypt) else {
            throw SecureStoreError.cantFormatData
        }
        
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(
            try retrieveKeys(localAuthStrings: configuration.localAuthStrings).privateKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            formattedData as CFData,
            &error
        ) else {
            if let error = error?.takeRetainedValue(),
               CFErrorGetDomain(error) == NSOSStatusErrorDomain as CFString,
               CFErrorGetCode(error) == -50 {
                try deleteKeys()
            }
            throw SecureStoreError.biometricErrorHandling(
                error: error?.takeRetainedValue(),
                defaultError: SecureStoreError.cantDecryptData
            )
        }
        
        guard let decryptedString = String(
            data: decryptedData as Data,
            encoding: .utf8
        ) else {
            throw SecureStoreError.cantDecodeData
        }
        
        return decryptedString
    }
}
