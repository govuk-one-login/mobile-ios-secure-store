import Foundation

protocol SigningService {
    func publicKey(didKey: Bool) throws -> Data
    func sign(data: Data) throws -> Data
}
