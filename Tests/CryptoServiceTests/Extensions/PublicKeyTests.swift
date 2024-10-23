import Foundation
import CryptoKit
@testable import CryptoService
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
}
