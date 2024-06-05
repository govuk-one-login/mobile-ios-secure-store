import Foundation

protocol DefaultsStore {
    func saveItem(encyptedItem: String, itemName: String)
    func getItem(itemName: String) -> String?
    func deleteItem(itemName: String)
}

struct UserDefaultsStore: DefaultsStore {
    let userDefaults: UserDefaults
    
    public init(userDefaults: UserDefaults = UserDefaults.standard) {
        self.userDefaults = userDefaults
    }
    
    // Saves the encrypted string to userdefaults for retrieval later
    public func saveItem(encyptedItem: String, itemName: String) {
        userDefaults.set(encyptedItem, forKey: itemName)
    }
    
    // Gets the encrypted string from userdefaults
    public func getItem(itemName: String) -> String? {
        userDefaults.string(forKey: itemName)
    }
    
    // Deletes the encrypted string from userdefaults
    public func deleteItem(itemName: String) {
        userDefaults.removeObject(forKey: itemName)
    }
}
