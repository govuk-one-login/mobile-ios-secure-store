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
}
