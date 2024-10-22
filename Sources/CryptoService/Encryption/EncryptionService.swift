import Foundation

protocol EncryptionService {
    func encryptDataWithPublicKey(dataToEncrypt: String) throws -> String
    func decryptDataWithPrivateKey(dataToDecrypt: String) throws -> String
}
