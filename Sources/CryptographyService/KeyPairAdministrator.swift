import Foundation
import LocalAuthentication

public enum KeyPairAdministratorError: Error {
    /// The public key could not be created
    case cantCreatePublicKey
    
    /// The private key could not be created
    case cantCreatePrivateKey
    
    /// No result was returned but no error was thrown by the `Security` framework
    case unknown
    
    /// Unable to delete the key pair
    case cantDeleteKeys
}

final class KeyPairAdministrator {
    // MARK: Cryptography Key dministration - creating, retrieving and deleting keys
    private let configuration: CryptographyServiceConfiguration
    
    public init(configuration: CryptographyServiceConfiguration) {
        self.configuration = configuration
    }
    
    func setup() throws -> KeyPair {
        let privateKey = try getPrivateKey()
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeyPairAdministratorError.cantCreatePublicKey
        }
        
        return .init(publicKey: publicKey, privateKey: privateKey)
    }
    
    /// query to get the private key from the keychain if it already exists
    private func getPrivateKey() throws -> SecKey {
        let privateKeyTag = Data("\(configuration.id)PrivateKey".utf8)
        
        var privateQuery: NSDictionary {
            let context = LAContext()
            if let localAuthStrings = configuration.localAuthStrings {
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
        
        guard privateStatus == errSecSuccess else {
            return try createPrivateKey()
        }
        
        // swiftlint:disable:next force_cast
        return privateKey as! SecKey
    }
    
    private func createPrivateKey() throws -> SecKey {
        let privateKeyTag = Data("\(configuration.id)PrivateKey".utf8)
        
        #if targetEnvironment(simulator)
        let requirement = [SecAccessControlCreateFlags]()
        #else
        let requirement = configuration.accessControlLevel.flags
        #endif
        
        var accessError: Unmanaged<CFError>?
        /// adds local auth requirements for when the private key is created
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           requirement,
                                                           &accessError) else {
            guard let error = accessError?.takeRetainedValue() as? Error else {
                throw KeyPairAdministratorError.unknown
            }
            throw error
        }
        
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: privateKeyTag,
                kSecAttrAccessControl: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw KeyPairAdministratorError.cantCreatePrivateKey
            }
            throw error
        }
        return privateKey
    }
    
    func deleteKeys() throws {
        let tag = Data("\(configuration.id)PrivateKey".utf8)
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tag]
        
        guard SecItemDelete(addquery as CFDictionary) == errSecSuccess else {
            throw KeyPairAdministratorError.cantDeleteKeys
        }
    }
}
