import CryptoKit
import Foundation
import Security

enum CryptoSigningServiceError: Error {
    case couldNotExportKey

    /// No result was returned but no error was thrown creating the signature by the `Security` framework
    case couldNotSignData
 }

final class CryptoSigningService: SigningService {
    private let keyStore: KeyStore

    /// The public key in did:key format, as defined in the w3c specification.
    /// https://w3c-ccg.github.io/did-method-key/
    var publicKey: Data {
        get throws {
            guard let data = try generateDidKey()
                .data(using: .utf8) else {
                throw CryptoSigningServiceError.couldNotExportKey
            }
            return data
        }
    }

    init(keyStore: KeyStore,
         algorithm: SecKeyAlgorithm = .ecdsaSignatureDigestX962SHA256) {
        self.keyStore = keyStore
    }

    /// Exports the public key from the Keychain to did:key format
    /// did:key specification: https://w3c-ccg.github.io/did-method-key/
    ///
    /// - Throws: CryptoSigningServiceError.couldNotExportKey
    /// - Returns: the public key in did:key format
    private func generateDidKey() throws -> String {
        let publicKey = try keyStore.publicKey
        guard let exportedKey = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            throw CryptoSigningServiceError.couldNotExportKey
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
        guard let signature = try SecKeyCreateSignature(
            keyStore.privateKey,
            .ecdsaSignatureRFC4754,
            hashData as CFData,
            &createError
        ) as Data? else {
            guard let error = createError?.takeRetainedValue() as? Error else {
                throw CryptoSigningServiceError.couldNotSignData
            }
            throw error
        }

        return signature
    }
}
