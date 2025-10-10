import Foundation

protocol JSONEncodable {
    func encode<T>(_ value: T) throws -> Data where T : Encodable
}

extension JSONEncoder: JSONEncodable { }
