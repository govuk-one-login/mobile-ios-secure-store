import Foundation

public enum EncryptionServiceError: Error {
    /// Can't encrypt data using public key from key pair
    case cantEncryptData
    
    /// Can't decrypt data using private key from key pair
    case cantDecryptData
}

public final class CryptoEncryptionService {
    private let keyStore: KeyStore
    private let keys: KeyPair
    
    init(keyStore: KeyStore) throws {
        self.keyStore = keyStore
        self.keys = try keyStore.setup()
    }
    
    public convenience init(configuration: CryptographyServiceConfiguration) throws {
        try self.init(keyStore: CryptoKeyStore(configuration: configuration))
    }
}

extension CryptoEncryptionService: EncryptionService {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw EncryptionServiceError.cantEncryptData
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(keys.publicKey,
                                                          .eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw EncryptionServiceError.cantEncryptData
            }
            throw error
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString()
        
        return encryptedString
    }
    
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws -> String {
        guard let formattedData = Data(base64Encoded: dataToDecrypt) else {
            throw EncryptionServiceError.cantDecryptData
        }
        
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        var error: Unmanaged<CFError>?
        guard let decryptData = SecKeyCreateDecryptedData(keys.privateKey,
                                                          .eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw EncryptionServiceError.cantDecryptData
            }
            throw error
        }
        
        guard let decryptedString = String(data: decryptData as Data, encoding: .utf8) else {
            throw EncryptionServiceError.cantDecryptData
        }
        
        return decryptedString
    }
}
