import Foundation

public protocol SecureStoreDefaults {
    func saveEncryptedItemToUserDefaults(encyptedItem: String, withKey key: String) throws
    func retrieveEncryptedItemFromUserDefaults(withKey key: String) throws -> String?
    func getItem(withKey key: String) throws -> String?
    func deleteItem(withKey key: String) throws
}

public struct SecureStoreUserDefaults: SecureStoreDefaults {
    let userDefaults: UserDefaults
    
    public init(userDefaults: UserDefaults = UserDefaults.standard) {
        self.userDefaults = userDefaults
    }
    
    // Saves the encrypted string to userdefaults for retrieval later
    public func saveEncryptedItemToUserDefaults(encyptedItem: String, withKey key: String) throws {
        do {
            userDefaults.set(encyptedItem, forKey: key)
        } catch {
            throw SecureStoreError.unableToRetrieveFromUserDefaults
        }
    }
    
    // Retrieves the encrypted string from userdefaults
    public func retrieveEncryptedItemFromUserDefaults(withKey key: String) throws -> String? {
        do {
            return userDefaults.string(forKey: key)
        } catch {
            throw SecureStoreError.unableToRetrieveFromUserDefaults
        }
    }
    
    // Gets the encrypted string from userdefaults
    public func getItem(withKey key: String) throws -> String? {
        return userDefaults.string(forKey: key)
    }
        
    // Deletes the encrypted string from userdefaults
    public func deleteItem(withKey key: String) throws {
        userDefaults.removeObject(forKey: key)
    }
}
