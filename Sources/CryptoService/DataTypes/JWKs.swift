struct JWKs: Encodable {
    let jwk: JWK
}

struct JWK: Encodable {
    let keyType = "EC"
    let intendedUse: IntendedUse = .signing
    let ellipticCurve: EllipticCurve
    let x: String
    let y: String
    
    enum CodingKeys: String, CodingKey {
        case x, y
        case keyType = "kty"
        case intendedUse = "use"
        case ellipticCurve = "cry"
    }
    
    enum IntendedUse: String, Encodable {
        case signing = "sig"
    }
    
    enum EllipticCurve: String, Encodable {
        case primeField256Bit = "P-256"
    }
}
