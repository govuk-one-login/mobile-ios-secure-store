@testable import CryptoService
import Foundation

final class MockKeyStore: KeyStore {
    var publicKey: SecKey = {
        let keyString = "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+E="
        let keyData = Data(base64Encoded: keyString)!
        
        return SecKeyCreateWithData(
            keyData as NSData,
            [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPublic
            ] as NSDictionary,
            nil
        )!
    }()

    var privateKey: SecKey = {
        let keyString = "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+GCHUxDELJbVEOXarPkRQFePo+1CYfTZkR/zKoSZxeADw=="
        let keyData = Data(base64Encoded: keyString)!
        
        return SecKeyCreateWithData(
            keyData as NSData,
            [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate
            ] as NSDictionary,
            nil
        )!
    }()

    func deleteKeys() throws { }
}
