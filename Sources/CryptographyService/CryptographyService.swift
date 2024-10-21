import BigInt
import LocalAuthentication
import CryptoKit
import Foundation

public enum CryptographicServiceError: Error {
    /// The public key external representation could not be created
    case couldNotCreatePublicKeyAsData
    
    /// No result was returned but no error was thrown creating the signature by the `Security` framework
    case unknownCreateSignatureError
    
    /// No result was returned but no error was thrown by verifying the signature by the `Security` framework
    case unknownVerifySignatureError
    
    /// Can't encrypt data using public key from key pair
    case cantEncryptData
    
    /// Can't decrypt data using private key from key pair
    case cantDecryptData
}

public final class CryptographyService {
    private let keyPairAdministrator: KeyPairAdministrator
    private let keys: KeyPair
    
    var publicKey: Data {
        get throws {
            guard let publicKeyData = SecKeyCopyExternalRepresentation(keys.publicKey, nil) else {
                throw CryptographicServiceError.couldNotCreatePublicKeyAsData
            }
            return publicKeyData as Data
        }
    }
    
    init(keyPairAdministrator: KeyPairAdministrator) throws {
        self.keyPairAdministrator = keyPairAdministrator
        self.keys = try keyPairAdministrator.setup()
    }
    
    public convenience init(configuration: CryptographyServiceConfiguration) throws {
        try self.init(keyPairAdministrator: KeyPairAdministrator(configuration: configuration))
    }
}

extension CryptographyService {
    func signAndVerifyData(data: Data) throws -> Data {
        var createError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(keys.privateKey,
                                                    .ecdsaSignatureMessageX962SHA256,
                                                    data as CFData,
                                                    &createError) as Data? else {
            guard let error = createError?.takeRetainedValue() as? Error else {
                throw CryptographicServiceError.unknownCreateSignatureError
            }
            throw error
        }
        
        let dataAsCFData = data as CFData
        let signatureAsCFData = signature as CFData
        
        var verifyError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(keys.publicKey,
                                    .ecdsaSignatureMessageX962SHA256,
                                    dataAsCFData,
                                    signatureAsCFData,
                                    &verifyError) else {
            guard let error = verifyError?.takeRetainedValue() as? Error else {
                throw CryptographicServiceError.unknownVerifySignatureError
            }
            throw error
        }
        
        return signature
    }
    
    /// Key compression eliminates redundant or unnecessary characters from the key data.
    /// A compressed key is a 32 byte value for the x coordinate prepended with 02 or a 03 to represent when y is even (02) or odd (03).
    /// Swift provides a function to do this but it is only available in iOS 16+.
    /// So this function is required for devices running older OS versions.
    ///
    /// - Parameters:
    ///     - publicKeyData: The key to be compressed
    func manuallyGenerateCompressedKey(publicKeyData: Data) -> Data {
        let publicKeyUInt8 = [UInt8](publicKeyData)
        let publicKeyXCoordinate = publicKeyUInt8[1...32]
        let prefix: UInt8 = 2 + (publicKeyData[publicKeyData.count - 1] & 1)
        let mutableXCoordinateArrayUInt8 = [UInt8](publicKeyXCoordinate)
        let prefixArray = [prefix]
        return Data(prefixArray + mutableXCoordinateArrayUInt8)
    }
    
    /// Returns a did:key representation of the wallet ownership key.
    /// did:key is a format for representing a public key. Specification:  https://w3c-ccg.github.io/did-method-key/
    func generateDidKey() throws -> String {
        guard let publicKey = SecKeyCopyExternalRepresentation(keys.publicKey, nil) else {
            throw CryptographicServiceError.couldNotCreatePublicKeyAsData
        }
        let publicKeyData = publicKey as Data
        
        var compressedKey: Data
        if #available(iOS 16.0, *) {
            let p256PublicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
            compressedKey = p256PublicKey.compressedRepresentation
        } else {
            compressedKey = manuallyGenerateCompressedKey(publicKeyData: publicKeyData)
        }
        
        let multicodecPrefix: [UInt8] = [0x80, 0x24] // P-256 elliptic curve
        let multicodecData = multicodecPrefix + compressedKey
        
        let base58Data = encodeBase58(Data(multicodecData))
        
        let didKey = "did:key:z" + base58Data
        
        return didKey
    }
    
    func encodeBase58(_ data: Data) -> String {
        var bigInt = BigUInt(data)
        let base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var result = ""
        
        while bigInt > 0 {
            let (quotient, remainder) = bigInt.quotientAndRemainder(dividingBy: 58)
            result = String(base58[String.Index(utf16Offset: Int(remainder), in: base58)]) + result
            bigInt = quotient
        }
        
        for byte in data {
            if byte != 0x00 {
                break
            }
            result = "1" + result
        }
        return result
    }
}

extension CryptographyService {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw CryptographicServiceError.cantEncryptData
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(keys.publicKey,
                                                          .eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw CryptographicServiceError.cantEncryptData
            }
            throw error
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])
        
        return encryptedString
    }
    
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws -> String {
        guard let formattedData = Data(base64Encoded: dataToDecrypt, options: [])  else {
            throw CryptographicServiceError.cantDecryptData
        }
        
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        var error: Unmanaged<CFError>?
        guard let decryptData = SecKeyCreateDecryptedData(keys.privateKey,
                                                          .eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw CryptographicServiceError.cantDecryptData
            }
            throw error
        }
        
        guard let decryptedString = String(data: decryptData as Data, encoding: .utf8) else {
            throw CryptographicServiceError.cantDecryptData
        }
        
        return decryptedString
    }
}
