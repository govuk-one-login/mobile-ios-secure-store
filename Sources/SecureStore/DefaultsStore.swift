import Foundation

protocol DefaultsStore {
    func saveItem(encyptedItem: String, itemName: String) throws
    func getItem(itemName: String) throws -> String?
    func deleteItem(itemName: String) throws
}

struct UserDefaultsStore: DefaultsStore {
    let userDefaults: UserDefaults
    
    public init(userDefaults: UserDefaults = UserDefaults.standard) {
        self.userDefaults = userDefaults
    }
    
    // Saves the encrypted string to userdefaults for retrieval later
    public func saveItem(encyptedItem: String, itemName: String) throws {
        return userDefaults.set(encyptedItem, forKey: itemName)
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
