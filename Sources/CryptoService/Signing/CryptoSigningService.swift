import BigInt
import Security
import CryptoKit
import Foundation

public enum SigningServiceError: Error {
    /// The public key external representation could not be created
    case couldNotCreatePublicKeyAsData
    
    /// No result was returned but no error was thrown creating the signature by the `Security` framework
    case unknownCreateSignatureError
}

public final class CryptoSigningService: SigningService {
    private let keyPairAdministrator: CryptoKeyStore
    private let keys: KeyPair
    
    var publicKey: Data {
        get throws {
            guard let publicKeyData = SecKeyCopyExternalRepresentation(keys.publicKey, nil) else {
                throw SigningServiceError.couldNotCreatePublicKeyAsData
            }
            return publicKeyData as Data
        }
    }
    
    init(keyPairAdministrator: CryptoKeyStore) throws {
        self.keyPairAdministrator = keyPairAdministrator
        self.keys = try keyPairAdministrator.setup()
    }
    
    public convenience init(configuration: CryptographyServiceConfiguration) throws {
        try self.init(keyPairAdministrator: CryptoKeyStore(configuration: configuration))
    }
    
    /// Exports the public key from the Keychain to did:key format
    /// did:key specification: https://w3c-ccg.github.io/did-method-key/
    ///
    /// - Throws: SigningServiceError.couldNotCreatePublicKeyAsData
    /// - Returns: the public key in did:key format
    private func generateDidKey() throws -> String {
        guard let exportedKey = SecKeyCopyExternalRepresentation(keys.publicKey, nil) else {
            throw SigningServiceError.couldNotCreatePublicKeyAsData
        }

        let publicKeyData = exportedKey as Data
        let p256PublicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
        let compressedKey = p256PublicKey.compressedRepresentation

        let multicodecPrefix: [UInt8] = [0x80, 0x24] // P-256 elliptic curve
        let multicodecData = multicodecPrefix + compressedKey

        let base58Data = Data(multicodecData).base58EncodedString()

        let didKey = "did:key:z" + base58Data

        return didKey
    }

    func sign(data: Data) throws -> Data {
        let hashDigest = SHA256.hash(data: data)
        let hashData = Data(hashDigest)

        var createError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            keys.privateKey,
            .ecdsaSignatureRFC4754,
            hashData as CFData,
            &createError
        ) as Data? else {
            guard let error = createError?.takeRetainedValue() as? Error else {
                throw SigningServiceError.unknownCreateSignatureError
            }
            throw error
        }

        return signature
    }
}
