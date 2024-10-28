import Foundation

public protocol SigningService {
    func publicKey(format: KeyFormat) throws -> Data
    func sign(data: Data) throws -> Data
}
