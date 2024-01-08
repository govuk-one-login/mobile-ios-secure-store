import Foundation

/// KeychainStorable
///
/// Used for saving items to keychain storage
public protocol KeychainStorable {
    func saveItem(item: String, itemName: String) throws
    func readItem(withName name: String) throws -> String?
    func deleteItem(keyToDelete: String) throws
    func deleteStore() throws
    func checkItemExists(withKey key: String) throws -> Bool
}
