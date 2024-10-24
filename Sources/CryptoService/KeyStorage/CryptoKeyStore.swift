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

/// Cryptographic Key administration - creating, retrieving and deleting keys
final class CryptoKeyStore: KeyStore {
    private let configuration: CryptoServiceConfiguration
    
    let privateKey: SecKey
    let publicKey: SecKey
    
    public convenience init(configuration: CryptoServiceConfiguration) throws {
        try self.init(configuration: configuration,
                      keyQuery: SecItemCopyMatching,
                      copyPublicKey: SecKeyCopyPublicKey)
    }
    
    init(configuration: CryptoServiceConfiguration,
         keyQuery: ((_ query: CFDictionary,
                     _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus),
         copyPublicKey: ((_ key: SecKey) -> SecKey?)) throws {
        self.configuration = configuration
        (privateKey, publicKey) = try Self.setup(
            configuration: configuration,
            keyQuery: keyQuery,
            copyPublicKey: copyPublicKey
        )
    }
    
    static func setup(
        configuration: CryptoServiceConfiguration,
        keyQuery: ((_ query: CFDictionary,
                    _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus),
        copyPublicKey: ((_ key: SecKey) -> SecKey?)
    ) throws -> (privateKey: SecKey, publicKey: SecKey) {
        let privateKey = try getPrivateKey(configuration: configuration,
                                           keyQuery: keyQuery)
        
        guard let publicKey = copyPublicKey(privateKey) else {
            throw KeyPairAdministratorError.cantCreatePublicKey
        }
        
        return (privateKey: privateKey, publicKey: publicKey)
    }
    
    /// query to get the private key from the keychain if it already exists
    static func getPrivateKey(
        configuration: CryptoServiceConfiguration,
        keyQuery: ((_ query: CFDictionary,
                    _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus)
    ) throws -> SecKey {
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
                kSecUseAuthenticationContext: context,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef: true
            ]
        }
        
        var privateKey: CFTypeRef?
        let privateStatus = keyQuery(privateQuery as CFDictionary, &privateKey)
        
        guard privateStatus == errSecSuccess else {
            return try createPrivateKey(configuration: configuration,
                                        createKey: SecKeyCreateRandomKey)
        }
        
        // swiftlint:disable:next force_cast
        return privateKey as! SecKey
    }
    
    static func createPrivateKey(
        configuration: CryptoServiceConfiguration,
        createKey: ((_ parameters: CFDictionary,
                     _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey?)
    ) throws -> SecKey {
        let privateKeyTag = Data("\(configuration.id)PrivateKey".utf8)
        
        #if targetEnvironment(simulator)
        let requirement = CryptoServiceConfiguration.AccessControlLevel.open.flags
        #else
        let requirement = configuration.accessControlLevel.flags
        #endif
        
        var accessError: Unmanaged<CFError>?
        /// adds local auth requirements for when the private key is created
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            requirement,
            &accessError
        ) else {
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
        guard let privateKey = createKey(attributes, &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw KeyPairAdministratorError.cantCreatePrivateKey
            }
            throw error
        }
        
        return privateKey
    }
    
    func deleteKeys(deletionMethod: ((_ query: CFDictionary) -> OSStatus) = SecItemDelete) throws {
        let tag = Data("\(configuration.id)PrivateKey".utf8)
        let addquery: NSDictionary = [kSecClass: kSecClassKey,
                         kSecAttrApplicationTag: tag]
        
        guard deletionMethod(addquery as CFDictionary) == errSecSuccess else {
            throw KeyPairAdministratorError.cantDeleteKeys
        }
    }
}
