import CryptoKit
import Foundation.NSJSONSerialization

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
    private let keyStore: CryptoKitKeyStore
    private let encoder: JSONEncoder
    
    /// The public key in either JWK or did:key format, as defined in IETF RFC7517 and the w3c specification.
    /// https://datatracker.ietf.org/doc/html/rfc7517
    /// https://w3c-ccg.github.io/did-method-key/
    public func publicKey(format: KeyFormat) throws -> Data {
        switch format {
        case .jwk:
            return try generateJWK()
        case .decentralisedIdentifier:
            return try generateDidKey()
        }
    }
    
    public convenience init(configuration: CryptoServiceConfiguration) throws {
        self.init(keyStore: try CryptoKitKeyStore(configuration: configuration),
                  encoder: JSONEncoder())
    }
    
    init(keyStore: CryptoKitKeyStore, encoder: JSONEncoder) {
        self.keyStore = keyStore
        self.encoder = encoder
    }
    
    private func generateJWK() throws -> Data {
        let jwks = JWKs(jwk: keyStore.publicKey.jwkRepresentation)
        return try encoder.encode(jwks)
    }
    
    private func generateDidKey() throws -> Data {
        let multicodecPrefix: [UInt8] = [0x80, 0x24] // P-256 elliptic curve
        let multicodecData = multicodecPrefix + keyStore.publicKey.compressedRepresentation

        let base58Data = Data(multicodecData).base58EncodedString()
        let didKeyString = "did:key:z" + base58Data

        guard let didKeyData = didKeyString.data(using: .utf8) else {
            throw SigningServiceError.couldNotCreateDIDKeyAsData
        }
        return didKeyData
    }

    public func sign(data: Data) throws -> Data {
        let hashDigest = SHA256.hash(data: data)
        let signature = try keyStore.privateKey.oneLoginSignature(for: hashDigest)
        return signature.rawRepresentation
    }
}
