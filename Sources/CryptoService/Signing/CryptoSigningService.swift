import BigInt
import CryptoKit
import Foundation
import Security

public enum SigningServiceError: Error {
    /// The public key external representation could not be created
    case couldNotCreatePublicKeyAsData
    
    /// The did key external representation could not be created
    case couldNotCreateJWKAsData
    
    /// The did key external representation could not be created
    case couldNotCreateDIDKeyAsData
    
    /// No result was returned but no error was thrown creating the signature by the `Security` framework
    case unknownCreateSignatureError
    
    // The keys could not be deleted
    case failedToDeleteKeys
}

public enum KeyFormat {
    case decentralisedIdentifier
    case jwk
}

public final class CryptoSigningService: SigningService {
    private let keyStore: KeyStore
    private let encoder: JSONEncodable
    
    private let keyCopyMethod: (
        _ key: SecKey,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData?
    
    private let createSignatureMethod: (
        _ key: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ dataToSign: CFData,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData?
    
    var publicKeyRepresentation: P256.Signing.PublicKey {
        get throws {
            var error: Unmanaged<CFError>?
            guard let exportedKey = keyCopyMethod(
                keyStore.publicKey,
                &error
            ) as? Data else {
                guard let error = error?.takeUnretainedValue()
                        as? Error else {
                    throw SigningServiceError.couldNotCreatePublicKeyAsData
                }
                throw error
            }
            do {
                return try P256.Signing.PublicKey(x963Representation: exportedKey)
            } catch {
                throw SigningServiceError.couldNotCreatePublicKeyAsData
            }
        }
    }
    
    public var jwkDictionary: [String: String] {
        get throws {
            try publicKeyRepresentation.jwkRepresentation.dictionary
        }
    }
    
    /// The public key in either JWK or did:key format, as defined in IETF RFC7517 and the w3c specification.
    /// https://datatracker.ietf.org/doc/html/rfc7517
    /// https://w3c-ccg.github.io/did-method-key/
    public func publicKey(format: KeyFormat) throws -> Data {
        switch format {
        case .jwk:
            return try generateJWK(publicKeyRepresentation)
        case .decentralisedIdentifier:
            return try generateDidKey(publicKeyRepresentation)
        }
    }
    
    public convenience init(configuration: CryptoServiceConfiguration) throws {
        self.init(
            keyStore: try CryptoKeyStore(configuration: configuration),
            encoder: JSONEncoder(),
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
    }
    
    init(
        keyStore: KeyStore,
        encoder: JSONEncodable,
        keyCopyMethod: @escaping (
            _ key: SecKey,
            _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
        ) -> CFData?,
        createSignatureMethod: @escaping (
            _ key: SecKey,
            _ algorithm: SecKeyAlgorithm,
            _ dataToSign: CFData,
            _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
        ) -> CFData?
    ) {
        self.keyStore = keyStore
        self.encoder = encoder
        self.keyCopyMethod = keyCopyMethod
        self.createSignatureMethod = createSignatureMethod
    }
    
    func generateJWK(_ key: P256.Signing.PublicKey) throws -> Data {
        let jwks = JWKs(jwk: key.jwkRepresentation)
        do {
            return try encoder.encode(jwks)
        } catch {
            throw SigningServiceError.couldNotCreateJWKAsData
        }
    }
    
    func generateDidKey(_ key: P256.Signing.PublicKey) throws -> Data {
        let multicodecPrefix: [UInt8] = [0x80, 0x24] // P-256 elliptic curve
        let multicodecData = multicodecPrefix + key.compressedRepresentation
        
        let base58Data = Data(multicodecData).base58EncodedString()
        let didKeyString = "did:key:z" + base58Data
        
        guard let didKeyData = didKeyString.data(using: .utf8) else {
            throw SigningServiceError.couldNotCreateDIDKeyAsData
        }
        return didKeyData
    }
    
    public func sign(data: Data) throws -> Data {
        let hashDigest = SHA256.hash(data: data)
        let hashData = Data(hashDigest)
        
        var createError: Unmanaged<CFError>?
        guard let signature = createSignatureMethod(
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
    
    public func deleteKeys() throws {
        do {
            try keyStore.deleteKeys()
        } catch {
            throw SigningServiceError.failedToDeleteKeys
        }
    }
    
    public static func deleteKeys(for id: String) throws {
        let keystore = try CryptoKeyStore(
            configuration: CryptoServiceConfiguration(
                id: id,
                accessControlLevel: .open
            )
        )
        
        try keystore.deleteKeys()
    }
}
