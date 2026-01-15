import Foundation
import LocalAuthentication

final class KeyManagerService {
    let configuration: SecureStorageConfiguration
    
    init(configuration: SecureStorageConfiguration) {
        self.configuration = configuration
        
        do {
            try createKeysIfNeeded(name: configuration.id)
        } catch {
            return
        }
    }
}

// MARK: Interaction with SecureEnclave
extension KeyManagerService {
    // Creating a key pair where the private key is stored in the Secure Enclave
    func createKeysIfNeeded(name: String) throws {
        
        // Check if key already exists
        do {
            _ = try retrievePrivateKey()
            return
        } catch {
            // Key does not exist yet, continue below to create it
        }
        
        #if targetEnvironment(simulator)
        let requirement = SecureStorageConfiguration.AccessControlLevel.open.flags
        #else
        let requirement = configuration.accessControlLevel.flags
        #endif
        
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           requirement,
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
        guard SecKeyCreateRandomKey(attributes, &error) != nil else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw SecureStoreError(.cantEncryptData)
            }
            throw error
        }
    }
    

    
    // Deletes the private key from the keychain
    func deleteKeys() throws {
        let tag = configuration.id.data(using: .utf8)!
        let deleteQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                          kSecAttrApplicationTag as String: tag]
        
        let status = SecItemDelete(deleteQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureStoreError(.cantDeleteKey)
        }
    }
    
    // Retrieve the private key and derive the public key from it
    func retrieveKeys(localAuthStrings: LocalAuthenticationLocalizedStrings? = nil) throws -> (
        publicKey: SecKey,
        privateKey: SecKey
    ) {
        let privateKey = try retrievePrivateKey(localAuthStrings: localAuthStrings)
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureStoreError(.cantGetPublicKeyFromPrivateKey)
        }

        return (publicKey, privateKey)
    }
    
    private func retrievePrivateKey(localAuthStrings: LocalAuthenticationLocalizedStrings? = nil) throws -> SecKey {
        let privateKeyTag = Data("\(configuration.id)".utf8)
        
        var privateQuery: NSDictionary {
            let context = LAContext()
            
            if let localAuthStrings {
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

        guard privateStatus == errSecSuccess else {
            throw SecureStoreError(.cantRetrieveKey)
        }

        // swiftlint:disable force_cast
        return privateKeyRef as! SecKey
        // swiftlint:enable force_cast
    }
}

// MARK: Encryption and Decryption
extension KeyManagerService {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        let publicKey = try retrieveKeys().publicKey
        
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw SecureStoreError(.cantEncodeData)
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(publicKey,
                                                          SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            throw SecureStoreError.biometricErrorHandling(
                error: error?.takeRetainedValue(),
                defaultError: SecureStoreError(.cantEncryptData)
            )
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])
        
        return encryptedString
    }
    
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws -> String {
        let privateKeyRepresentation = try retrieveKeys(localAuthStrings: configuration.localAuthStrings).privateKey
        
        guard let formattedData = Data(base64Encoded: dataToDecrypt, options: [])  else {
            throw SecureStoreError(.cantFormatData)
        }
        
        var error: Unmanaged<CFError>?
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        guard let decryptData = SecKeyCreateDecryptedData(privateKeyRepresentation,
                                                          SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            throw SecureStoreError.biometricErrorHandling(
                error: error?.takeRetainedValue(),
                defaultError: SecureStoreError(.cantDecryptData)
            )
        }
        
        guard let decryptedString = String(data: decryptData as Data, encoding: .utf8) else {
            throw SecureStoreError(.cantDecodeData)
        }
        
        return decryptedString
    }
}
