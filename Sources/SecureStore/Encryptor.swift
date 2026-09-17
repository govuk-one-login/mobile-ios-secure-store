/// An encryptor allows you to encrypt a value (i.e. a `String`)
///
/// - SeeAlso: ``EncryptedSecureStorable/encryptor`` on how to obtain an instance
public protocol Encryptor {
    func encrypt(value: String) throws -> String
}
