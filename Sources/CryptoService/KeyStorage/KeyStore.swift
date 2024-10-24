import Security

public protocol KeyStore {
    var publicKey: SecKey { get }
    var privateKey: SecKey { get }
    init(configuration: CryptoServiceConfiguration) throws
    func deleteKeys(deletionMethod: (_ query: CFDictionary) -> OSStatus) throws
}
