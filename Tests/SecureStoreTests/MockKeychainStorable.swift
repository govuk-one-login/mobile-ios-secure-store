import Foundation
import SecureStore

class MockSecureStore: SecureStoreDefaults {
    var didCallSaveEncryptedItem: Bool = false
    var didCallRetrieveEncryptedItem: Bool = false
    var didCallGetItem: Bool = false
    var didCallDeleteItem: Bool = false

    func saveEncryptedItemToUserDefaults(encyptedItem: String, withKey key: String) throws {
        didCallSaveEncryptedItem = true
    }
    
    func retrieveEncryptedItemFromUserDefaults(withKey key: String) throws -> String? {
        didCallRetrieveEncryptedItem = true
        return nil
    }
    
    func getItem(withKey key: String) throws -> String? {
        didCallGetItem = true
        return nil
    }
    
    func deleteItem(withKey key: String) throws {
        didCallDeleteItem = true
    }
}
