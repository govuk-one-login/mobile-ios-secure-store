/// SecureStorable
///
/// Used for saving items to keychain storage
public protocol SecureStorable {
    func saveItem(item: String, itemName: String) throws
    func readItem(itemName: String) throws -> String
    func deleteItem(itemName: String)
    func delete() throws
    func checkItemExists(itemName: String) -> Bool
}
