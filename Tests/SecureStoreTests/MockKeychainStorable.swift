import Foundation
@testable import SecureStore

class MockSecureStore: DefaultsStore {
    var didCallSaveItem: Bool = false
    var didCallGetItem: Bool = false
    var didCallDeleteItem: Bool = false

    func saveItem(encyptedItem: String, itemName: String) throws {
        didCallSaveItem = true
    }
    
    func getItem(itemName: String) throws -> String? {
        didCallGetItem = true
        return nil
    }
    
    func deleteItem(itemName: String) throws {
        didCallDeleteItem = true
    }
}
