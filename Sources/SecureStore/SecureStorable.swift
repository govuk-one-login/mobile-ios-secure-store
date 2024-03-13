/// SecureStorable
///
/// Used for saving items to keychain storage
public protocol SecureStorable {
    func saveItem(item: String, itemName: String) throws
    func readItem(itemName: String, contextStrings: [String:String]?) throws -> String?
    func deleteItem(itemName: String) throws
    func delete() throws
    func checkItemExists(itemName: String) throws -> Bool
}
