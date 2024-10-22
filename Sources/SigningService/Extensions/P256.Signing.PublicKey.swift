import CryptoKit
import Foundation

extension P256.Signing.PublicKey {
    @backDeployed(before: iOS 16)
    public var compressedRepresentation: Data {
        _compressedRepresentation
    }

    @usableFromInline
    var _compressedRepresentation: Data {
        let publicKeyData = x963Representation
        let publicKeyUInt8 = [UInt8](publicKeyData)
        let publicKeyXCoordinate = publicKeyUInt8[1...32]
        let prefix: UInt8 = 2 + (publicKeyData[publicKeyData.count - 1] & 1)
        let mutableXCoordinateArrayUInt8 = [UInt8](publicKeyXCoordinate)
        let prefixArray = [prefix]
        return Data(prefixArray + mutableXCoordinateArrayUInt8)
    }
}
