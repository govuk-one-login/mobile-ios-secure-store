import CryptoKit
import LocalAuthentication
import Foundation.NSData

final class CryptoKitKeyStore {
    private let configuration: CryptoServiceConfiguration

    let privateKey: SecureEnclave.P256.Signing.PrivateKey
    let publicKey: P256.Signing.PublicKey
    
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
    ) throws -> (privateKey: SecureEnclave.P256.Signing.PrivateKey,
                 publicKey: P256.Signing.PublicKey) {
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        return (privateKey: privateKey, publicKey: publicKey)
    }
}
