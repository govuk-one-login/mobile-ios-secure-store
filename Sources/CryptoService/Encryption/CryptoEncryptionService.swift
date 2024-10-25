import Foundation

public enum EncryptionServiceError: Error {
    /// Can't encrypt data using public key from key pair
    case cantEncryptData
    
    /// Can't decrypt data using private key from key pair
    case cantDecryptData
}

public final class CryptoEncryptionService {
    private let keyStore: KeyStore
    
    public convenience init(configuration: CryptoServiceConfiguration) throws {
        self.init(keyStore: try CryptoKeyStore(configuration: configuration))
    }
    
    init(keyStore: KeyStore) {
        self.keyStore = keyStore
    }
    
    public func encryptData(dataToEncrypt: String) throws -> String {
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw EncryptionServiceError.cantEncryptData
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(
            keyStore.publicKey,
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
    
    public func decryptData(dataToDecrypt: String) throws -> String {
        guard let formattedData = Data(base64Encoded: dataToDecrypt) else {
            throw EncryptionServiceError.cantDecryptData
        }
        
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        var error: Unmanaged<CFError>?
        guard let decryptData = SecKeyCreateDecryptedData(keyStore.privateKey,
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
