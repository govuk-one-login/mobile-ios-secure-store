import GDSUtilities

/// SecureStorable - used for saving items to keychain storage
// TODO: DCMAW-18331 delete protocol
public protocol SecureStorable {
    func saveItem(item: String, itemName: String) throws
    func readItem(itemName: String) throws -> String
    func deleteItem(itemName: String)
    func delete() throws
    func checkItemExists(itemName: String) -> Bool
}

public protocol SecureStorableV2 {
    func saveItem(item: String, itemName: String) throws
    func readItem(itemName: String) throws(SecureStoreErrorV2) -> String
    func deleteItem(itemName: String)
    func delete() throws
    func checkItemExists(itemName: String) -> Bool
}
