import GDSUtilities

@available(*, deprecated, renamed: "SecureStorable")
public typealias SecureStorableV2 = SecureStorable

public protocol SecureStorable {
    func saveItem(item: String, itemName: String) throws
    func readItem(itemName: String) throws(SecureStoreError) -> String
    func deleteItem(itemName: String)
    func delete() throws
    func checkItemExists(itemName: String) -> Bool
}

/// A ``SecureStorable`` that support a two-step appoach to encryption prior to saving an item.
public protocol EncryptedSecureStorable: SecureStorable {
    func encryptor() throws -> Encryptor
    func save(using encryptor: Encryptor, item: String, itemName: String) throws
}
