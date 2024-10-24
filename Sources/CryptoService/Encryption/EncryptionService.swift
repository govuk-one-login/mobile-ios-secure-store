import Foundation

public protocol EncryptionService {
    func encryptData(dataToEncrypt: String) throws -> String
    func decryptData(dataToDecrypt: String) throws -> String
}
