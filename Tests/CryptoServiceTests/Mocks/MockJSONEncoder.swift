@testable import CryptoService
import Foundation

struct MockJSONEncoder: JSONDataEncoder {
    var errorFromEncode: Error?
    
    func encode<T>(_ value: T) throws -> Data where T: Encodable {
        if let errorFromEncode {
            throw errorFromEncode
        } else {
            return Data()
        }
    }
}
