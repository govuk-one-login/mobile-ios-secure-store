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
    
    var JWT: Data {
        get throws {
            let publicKeyUInt8 = [UInt8](x963Representation)
            let xCoordinate = publicKeyUInt8[1...32]
            let yCoordinate = publicKeyUInt8[33...64]
            let xCoordinateData = Data([UInt8](xCoordinate))
            let yCoordinateData = Data([UInt8](yCoordinate))
            let xCoordinateBase64 = xCoordinateData.base64EncodedString()
            let yCoordinateBase64 = yCoordinateData.base64EncodedString()
            let appCheckJWKBody = AppCheckJWTBody(x: xCoordinateBase64,
                                                  y: yCoordinateBase64)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            return try encoder.encode(AppCheckJWT(jwk: appCheckJWKBody))
        }
    }
}

struct AppCheckJWT: Encodable {
    let jwk: AppCheckJWTBody
}

struct AppCheckJWTBody: Encodable {
    let kty = "EC"
    let use = "sig"
    let crv = "P-256"
    let x: String
    let y: String
}
