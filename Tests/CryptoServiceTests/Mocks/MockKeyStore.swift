@testable import CryptoService
import Foundation

struct MockKeyStore: KeyStore {
    func setup() throws -> KeyPair {
        return try KeyPair(publicKey: publicKey, privateKey: privateKey)
    }
    
    func deleteKeys() throws { }
    
    var publicKey: SecKey {
        get throws {
            let keyString = "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+E="
            let keyData = Data(base64Encoded: keyString)!
            
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(
                keyData as NSData,
                [
                    kSecAttrKeyType: kSecAttrKeyTypeEC,
                    kSecAttrKeyClass: kSecAttrKeyClassPublic
                ] as NSDictionary,
                &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }

            return key
        }
    }

    var privateKey: SecKey {
        get throws {
            let keyString = "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+GCHUxDELJbVEOXarPkRQFePo+1CYfTZkR/zKoSZxeADw=="
            let keyData = Data(base64Encoded: keyString)!
            
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(
                keyData as NSData,
                [
                    kSecAttrKeyType: kSecAttrKeyTypeEC,
                    kSecAttrKeyClass: kSecAttrKeyClassPrivate
                ] as NSDictionary,
                &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }

            return key
        }
    }
}
