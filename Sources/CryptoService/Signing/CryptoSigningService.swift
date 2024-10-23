import BigInt
import CryptoKit
import Foundation
import Security

public enum SigningServiceError: Error {
    /// The public key external representation could not be created
    case couldNotCreatePublicKeyAsData
    
    /// The did key external representation could not be created
    case couldNotCreateDIDKeyAsData
    
    /// No result was returned but no error was thrown creating the signature by the `Security` framework
    case unknownCreateSignatureError
}

public final class CryptoSigningService: SigningService {
    private let keyStore: KeyStore
    private let keys: KeyPair
    
    /// The public key in either raw or did:key format, as defined in the w3c specification.
    /// https://w3c-ccg.github.io/did-method-key/
    func publicKey(didKey: Bool = false) throws -> Data {
        guard let exportedKey = SecKeyCopyExternalRepresentation(keys.publicKey, nil)
                as? Data else {
            throw SigningServiceError.couldNotCreatePublicKeyAsData
        }
        guard didKey else {
            return exportedKey
        }
        guard let data = try generateDidKey(exportedKey)
            .data(using: .utf8) else {
            throw SigningServiceError.couldNotCreateDIDKeyAsData
        }
        return data
    }
    
    init(keyStore: KeyStore) throws {
        self.keyStore = keyStore
        self.keys = try keyStore.setup()
    }
    
    public convenience init(configuration: CryptographyServiceConfiguration) throws {
        try self.init(keyStore: CryptoKeyStore(configuration: configuration))
    }
    
    /// Exports the public key from the Keychain to did:key format
    /// did:key specification: https://w3c-ccg.github.io/did-method-key/
    ///
    /// - Throws: SigningServiceError.couldNotCreatePublicKeyAsData
    /// - Returns: the public key in did:key format
    private func generateDidKey(_ key: Data) throws -> String {
        let p256PublicKey = try P256.Signing.PublicKey(x963Representation: key)
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
            guard let error = createError?.takeRetainedValue()
                    as? Error else {
                throw SigningServiceError.unknownCreateSignatureError
            }
            throw error
        }

        return signature
    }
}
