import Security

public protocol KeyStore {
    var publicKey: SecKey { get }
    var privateKey: SecKey { get }
    
    func deleteKeys() throws
}
