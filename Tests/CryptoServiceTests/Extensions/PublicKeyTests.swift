import enum CryptoKit.P256
@testable import CryptoService
import Foundation
import Testing

struct PublicKeyTests {
    @Test
    func testBackDeployment() throws {
        let data = try #require(Data(
            base64Encoded: "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+E="
        ))
        
        let sut = try P256.Signing.PublicKey(
            x963Representation: data
        )

        #expect(sut.compressedRepresentation == sut._compressedRepresentation)
    }
    
    @Test
    @available(iOS 16, macOS 13, *)
    func jwkRepresentation() throws {
        let key = try P256.Signing.PublicKey(pemRepresentation: """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE18wHLeIgW9wVN6VD1Txgpqy2LszY
        kMf6J8njVAibvhP5Xh1LhRosyA//h9jiPyKvtyXVNeUV0CBzHnmjtORxIA==
        -----END PUBLIC KEY-----
        """)
        
        let constructedJWK = JWK(x: "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
                                 y: "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA")
        
        #expect(key.jwkRepresentation.keyType == .ec)
        #expect(key.jwkRepresentation.keyType == constructedJWK.keyType)
        #expect(key.jwkRepresentation.intendedUse == .signing)
        #expect(key.jwkRepresentation.intendedUse == constructedJWK.intendedUse)
        #expect(key.jwkRepresentation.ellipticCurve == .primeField256Bit)
        #expect(key.jwkRepresentation.ellipticCurve == constructedJWK.ellipticCurve)
        #expect(key.jwkRepresentation.x == constructedJWK.x)
        #expect(key.jwkRepresentation.y == constructedJWK.y)
    }
}
