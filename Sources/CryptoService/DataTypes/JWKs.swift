struct JWKs: Encodable {
    let jwk: JWK
}

struct JWK: Encodable {
    let kty = "EC"
    let use = "sig"
    let crv = "P-256"
    let x: String
    let y: String
}
