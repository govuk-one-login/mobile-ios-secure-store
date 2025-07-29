import BigInt
import CryptoKit
@testable import CryptoService
import Foundation
import Security

public final class MockSigningService: SigningService {
    private var didCallPublicKey: Bool = false
    private var didCallGenerateJWK: Bool = false
    private var didCallGenerateDidKey: Bool = false
    private var didCallSign: Bool = false
    private var didCallDeleteKeys: Bool = false
    
    private let keyStore: KeyStore
    private let encoder: JSONEncoder
    
    public func publicKey(format: KeyFormat) throws -> Data {
        didCallPublicKey = true
        return Data()
    }
    
    public convenience init(configuration: CryptoServiceConfiguration) throws {
        self.init(
            keyStore: MockKeyStore(),
            encoder: JSONEncoder()
        )
    }
    
    init(
        keyStore: KeyStore,
        encoder: JSONEncoder
    ) {
        self.keyStore = keyStore
        self.encoder = encoder
    }
    
    private func generateJWK(_ key: P256.Signing.PublicKey) throws -> Data {
        didCallGenerateJWK = true
        return Data()
    }
    
    private func generateDidKey(_ key: P256.Signing.PublicKey) throws -> Data {
        didCallGenerateDidKey = true
        return Data()
    }
    
    public func sign(data: Data) throws -> Data {
        didCallSign = true
        return Data()
    }
    
    public func deleteKeys() throws {
        didCallDeleteKeys = true
    }
    
    public static func deleteItem(for id: String) throws {
        let mockKeyStore = MockKeyStore()
        try mockKeyStore.deleteKeys()
    }
}
