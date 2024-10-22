import Foundation

protocol SigningService {
    var publicKey: Data { get throws }
    func sign(data: Data) throws -> Data
}
