import Foundation

protocol SigningService {
    var publicKey: Data { get throws }
    func signAndVerifyData(data: Data) throws -> Data
}
