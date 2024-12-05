import CryptoKit
import LocalAuthentication
import Foundation.NSData

protocol CryptoECDSASignature {
    var rawRepresentation: Data { get }
}

extension P256.Signing.ECDSASignature: CryptoECDSASignature { }

protocol CryptoPrivateKey {
    var dataRepresentation: Data { get }
    func oneLoginSignature<D>(for digest: D) throws -> CryptoECDSASignature where D : Digest
}

extension SecureEnclave.P256.Signing.PrivateKey: CryptoPrivateKey {
    func oneLoginSignature<D>(for digest: D) throws -> any CryptoECDSASignature where D : Digest {
        try signature(for: digest)
    }
}

protocol CryptoPublicKey {
    var compressedRepresentation: Data { get }
    var jwkRepresentation: JWK { get }
}

extension P256.Signing.PublicKey: CryptoPublicKey { }

final class CryptoKitKeyStore {
    private let configuration: CryptoServiceConfiguration

    let privateKey: CryptoPrivateKey
    let publicKey: CryptoPublicKey
    
    init(
        configuration: CryptoServiceConfiguration
    ) throws {
        self.configuration = configuration
        (privateKey, publicKey) = try Self.setup(
            configuration: configuration
        )
    }

    static func setup(
        configuration: CryptoServiceConfiguration
    ) throws -> (privateKey: CryptoPrivateKey, publicKey: CryptoPublicKey) {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            configuration.accessControlLevel.flags,
            &accessError
        ) else {
            guard let error = accessError?.takeRetainedValue() as? Error else {
                throw KeyPairAdministratorError.unknown
            }
            throw error
        }
        
        let context = LAContext()
        if let localAuthStrings = configuration.localAuthStrings {
            // Local Authentication prompt strings
            context.localizedReason = localAuthStrings.localizedReason
            context.localizedFallbackTitle = localAuthStrings.localisedFallbackTitle
            context.localizedCancelTitle = localAuthStrings.localisedCancelTitle
        }
        
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access,
                                                                   authenticationContext: context)
        UserDefaults.standard.set(privateKey, forKey: configuration.id)
        let publicKey = privateKey.publicKey
        return (privateKey: privateKey, publicKey: publicKey)
    }
}
