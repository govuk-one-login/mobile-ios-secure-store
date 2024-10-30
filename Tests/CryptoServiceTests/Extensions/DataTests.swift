@testable import CryptoService
import Foundation
import Testing

struct DataTests {
    @Test
    func base58Encoding() {
        let bytes: [UInt8] = [255, 254, 253, 252]
        let data = Data(bytes)
        #expect(data.base58EncodedString() == "7YXVWT")
    }
    
    @Test
    func base64URLEncodedString() throws {
        let publicKeyData = Data("""
            BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+E=
        """.utf8)
        let urlEncoded = publicKeyData.base64URLEncodedString
        
        #expect(!urlEncoded.contains("="))
        #expect(!urlEncoded.contains("+"))
        #expect(!urlEncoded.contains("/"))
    }
}
