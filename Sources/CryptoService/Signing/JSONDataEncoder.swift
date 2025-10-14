import Foundation

protocol JSONDataEncoder {
    func encode<T>(_ value: T) throws -> Data where T: Encodable
}

extension JSONEncoder: JSONDataEncoder { }
