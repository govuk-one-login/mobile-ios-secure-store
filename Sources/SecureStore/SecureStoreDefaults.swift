import Foundation

public protocol SecureStoreDefaults {
    func saveEncryptedItemToUserDefaults(encyptedItem: String, itemName: String) throws
    func retrieveEncryptedItemFromUserDefaults(itemName: String) throws -> String?
    func getItem(itemName: String) throws -> String?
    func deleteItem(itemName: String) throws
}

struct SecureStoreUserDefaults: SecureStoreDefaults {
    let userDefaults: UserDefaults
    
    public init(userDefaults: UserDefaults = UserDefaults.standard) {
        self.userDefaults = userDefaults
    }
    
    // Saves the encrypted string to userdefaults for retrieval later
    public func saveEncryptedItemToUserDefaults(encyptedItem: String, itemName: String) throws {
        return userDefaults.set(encyptedItem, forKey: itemName)
    }
    
    // Retrieves the encrypted string from userdefaults
    public func retrieveEncryptedItemFromUserDefaults(itemName: String) throws -> String? {
        return userDefaults.string(forKey: itemName)
    }
    
    // Gets the encrypted string from userdefaults
    public func getItem(itemName: String) throws -> String? {
        return userDefaults.string(forKey: itemName)
    }
        
    // Deletes the encrypted string from userdefaults
    public func deleteItem(itemName: String) throws {
        userDefaults.removeObject(forKey: itemName)
    }
}
