import Security

protocol KeyStore {
    var publicKey: SecKey { get throws }
    var privateKey: SecKey { get throws }
}
