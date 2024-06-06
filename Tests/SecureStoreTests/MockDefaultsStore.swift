import Foundation
@testable import SecureStore

class MockDefaultsStore: DefaultsStore {
    var didCallSaveItem: Bool = false
    var didCallGetItem: Bool = false
    var didCallDeleteItem: Bool = false
    
    func saveItem(encyptedItem: String, itemName: String) {
        didCallSaveItem = true
    }
    
    func getItem(itemName: String) -> String? {
        didCallGetItem = true
        return nil
    }
    
    func deleteItem(itemName: String) {
        didCallDeleteItem = true
    }
}
