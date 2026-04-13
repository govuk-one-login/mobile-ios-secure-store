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
