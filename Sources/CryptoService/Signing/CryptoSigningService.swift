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

public enum KeyFormat {
    case decentralisedIdentifier
    case jwk
}

public final class CryptoSigningService: SigningService {
    private let keyStore: KeyStore
    private let encoder: JSONEncoder
    
    /// The public key in either JWK or did:key format, as defined in IETF RFC7517 and the w3c specification.
    /// https://datatracker.ietf.org/doc/html/rfc7517
    /// https://w3c-ccg.github.io/did-method-key/
    public func publicKey(format: KeyFormat) throws -> Data {
        guard let exportedKey = SecKeyCopyExternalRepresentation(keyStore.publicKey, nil)
                as? Data else {
            throw SigningServiceError.couldNotCreatePublicKeyAsData
        }
        let p256PublicKey = try P256.Signing.PublicKey(x963Representation: exportedKey)

        switch format {
        case .decentralisedIdentifier:
            guard let didKey = generateDidKey(p256PublicKey)
                .data(using: .utf8) else {
                throw SigningServiceError.couldNotCreateDIDKeyAsData
            }
            return didKey
        case .jwk:
            return try generateJWK(p256PublicKey)
        }
    }
    
    public convenience init(configuration: CryptoServiceConfiguration) throws {
        self.init(keyStore: try CryptoKeyStore(configuration: configuration),
                  encoder: JSONEncoder())
    }
    
    init(keyStore: KeyStore, encoder: JSONEncoder) {
        self.keyStore = keyStore
        self.encoder = encoder
    }
    
    private func generateJWK(_ key: P256.Signing.PublicKey) throws -> Data {
        let jwk = key.jwkRepresentation
        let jwks = JWKs(jwk: jwk)
        return try encoder.encode(jwks)
    }
    
    private func generateDidKey(_ key: P256.Signing.PublicKey) -> String {
        let compressedKey = key.compressedRepresentation

        let multicodecPrefix: [UInt8] = [0x80, 0x24] // P-256 elliptic curve
        let multicodecData = multicodecPrefix + compressedKey

        let base58Data = Data(multicodecData).base58EncodedString()
        let didKey = "did:key:z" + base58Data

        return didKey
    }

    public func sign(data: Data) throws -> Data {
        let hashDigest = SHA256.hash(data: data)
        let hashData = Data(hashDigest)

        var createError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            keyStore.privateKey,
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
