struct JWKs: Encodable {
    let jwk: JWK
}

/// JWK compliant with formating described in: https://datatracker.ietf.org/doc/html/rfc7517#section-4
struct JWK: Encodable {
    let keyType = "EC"
    let intendedUse: IntendedUse = .signing
    let ellipticCurve: EllipticCurve = .primeField256Bit
    let x: String
    let y: String
    
    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case intendedUse = "use"
        case ellipticCurve = "crv"
        case x, y
    }
    
    enum IntendedUse: String, Encodable {
        case signing = "sig"
    }
    
    enum EllipticCurve: String, Encodable {
        case primeField256Bit = "P-256"
    }
    
    var dictionary: [String: String] {
        [
            "kty": keyType,
            "use": intendedUse.rawValue,
            "crv": ellipticCurve.rawValue,
            "x": x,
            "y": y
        ]
    }
}
