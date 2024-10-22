protocol KeyStore {
    func setup() throws -> KeyPair
    func deleteKeys() throws
}
