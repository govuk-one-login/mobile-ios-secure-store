import Security

public protocol KeyStore {
    var publicKey: SecKey { get }
    var privateKey: SecKey { get }
    init(configuration: CryptoServiceConfiguration) throws
    func deleteKeys() throws
}
