import Foundation

public enum CryptographyServiceError: Error {
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

public final class EncryptionService {
    private let keyPairAdministrator: KeyPairAdministrator
    private let keys: KeyPair
    
    init(keyPairAdministrator: KeyPairAdministrator) throws {
        self.keyPairAdministrator = keyPairAdministrator
        self.keys = try keyPairAdministrator.setup()
    }
    
    public convenience init(configuration: CryptographyServiceConfiguration) throws {
        try self.init(keyPairAdministrator: KeyPairAdministrator(configuration: configuration))
    }
}

extension EncryptionService {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String {
        guard let formattedData = dataToEncrypt.data(using: String.Encoding.utf8) else {
            throw CryptographyServiceError.cantEncryptData
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptData = SecKeyCreateEncryptedData(keys.publicKey,
                                                          .eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw CryptographyServiceError.cantEncryptData
            }
            throw error
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])
        
        return encryptedString
    }
    
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws -> String {
        guard let formattedData = Data(base64Encoded: dataToDecrypt, options: [])  else {
            throw CryptographyServiceError.cantDecryptData
        }
        
        // Pulls from Secure Enclave - here is where we will look for FaceID/Passcode
        var error: Unmanaged<CFError>?
        guard let decryptData = SecKeyCreateDecryptedData(keys.privateKey,
                                                          .eciesEncryptionStandardX963SHA256AESGCM,
                                                          formattedData as CFData,
                                                          &error) else {
            guard let error = error?.takeRetainedValue() as? Error else {
                throw CryptographyServiceError.cantDecryptData
            }
            throw error
        }
        
        guard let decryptedString = String(data: decryptData as Data, encoding: .utf8) else {
            throw CryptographyServiceError.cantDecryptData
        }
        
        return decryptedString
    }
}
