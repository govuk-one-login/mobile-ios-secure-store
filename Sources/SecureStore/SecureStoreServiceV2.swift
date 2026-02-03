import Foundation

public class SecureStoreServiceV2 {
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
extension SecureStoreServiceV2: SecureStorableV2 {
    public func checkItemExists(itemName: String) -> Bool {
        guard secureStoreDefaults.getItem(itemName: itemName) != nil else { return false }
        return true
    }
    
    public func readItem(itemName: String) throws -> String {
        guard let encryptedData = secureStoreDefaults.getItem(itemName: itemName) else {
            throw SecureStoreErrorV2(.unableToRetrieveFromUserDefaults)
        }
        return try keyManagerService.decryptDataWithPrivateKeyV2(dataToDecrypt: encryptedData)
    }
    
    public func saveItem(item: String, itemName: String) throws {
        let encryptedData = try keyManagerService.encryptDataWithPublicKeyV2(dataToEncrypt: item)
        secureStoreDefaults.saveItem(encyptedItem: encryptedData, itemName: itemName)
    }
    
    public func deleteItem(itemName: String) {
        secureStoreDefaults.deleteItem(itemName: itemName)
    }
    
    public func delete() throws {
        try keyManagerService.deleteKeys()
    }
}
