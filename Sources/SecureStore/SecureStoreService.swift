import Foundation
import LocalAuthentication

public class SecureStoreService {
    let keyManagerService: KeyManagerService
    let secureStoreDefaults: DefaultsStore
    
    public convenience init(configuration: SecureStorageConfiguration) {
        self.init(keyManagerService: KeyManagerService(configuration: configuration),
                  defaultsStore: UserDefaultsStore())
    }
    
    init(keyManagerService: KeyManagerService,
         defaultsStore: DefaultsStore) {
        self.keyManagerService = keyManagerService
        self.secureStoreDefaults = defaultsStore
    }
}

// MARK: SecureStorable Conformance
extension SecureStoreService: SecureStorable {
    public func checkItemExists(itemName: String) -> Bool {
        guard secureStoreDefaults.getItem(itemName: itemName) != nil else { return false }
        return true
    }
    
    public func readItem(itemName: String) throws -> String {
        guard let encryptedData = secureStoreDefaults.getItem(itemName: itemName) else {
            throw SecureStoreError.unableToRetrieveFromUserDefaults
        }
        return try keyManagerService.decryptDataWithPrivateKey(dataToDecrypt: encryptedData)
    }
    
    public func saveItem(item: String, itemName: String) throws {
        let encryptedData = try keyManagerService.encryptDataWithPublicKey(dataToEncrypt: item)
        secureStoreDefaults.saveItem(encyptedItem: encryptedData, itemName: itemName)
    }
    
    public func deleteItem(itemName: String) {
        secureStoreDefaults.deleteItem(itemName: itemName)
    }
    
    public func delete() throws {
        try keyManagerService.deleteKeys()
    }
}
