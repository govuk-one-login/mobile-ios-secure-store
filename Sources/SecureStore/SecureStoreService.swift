import Foundation
import LocalAuthentication

public class SecureStoreService {
    let secureStoreDefaults: DefaultsStore
    let keyManagerService: KeyManagerService
    private let configuration: SecureStorageConfiguration

    public convenience init(configuration: SecureStorageConfiguration) {
        self.init(configuration: configuration, defaultsStore: UserDefaultsStore())
    }

    init(configuration: SecureStorageConfiguration, defaultsStore: DefaultsStore) {
        self.configuration = configuration
        self.secureStoreDefaults = defaultsStore
        self.keyManagerService = KeyManagerService(configuration: configuration)
    }
}

// MARK: SecureStorable Conformance
extension SecureStoreService: SecureStorable {
    public func checkItemExists(itemName: String) throws -> Bool {
        guard try secureStoreDefaults.getItem(itemName: itemName) != nil else { return false }
        return true
    }

    public func readItem(itemName: String) throws -> String? {
        guard let encryptedData = try secureStoreDefaults.getItem(itemName: itemName) else {
            throw SecureStoreError.unableToRetrieveFromUserDefaults
        }
        return try keyManagerService.decryptDataWithPrivateKey(dataToDecrypt: encryptedData,
                                                               localAuthStrings: configuration.localAuthStrings)
    }

    public func saveItem(item: String, itemName: String) throws {
        _ = try keyManagerService.retrieveKeys()

        guard let encryptedData = try keyManagerService.encryptDataWithPublicKey(dataToEncrypt: item) else {
            return
        }

        try secureStoreDefaults.saveItem(encyptedItem: encryptedData, itemName: itemName)
    }

    public func deleteItem(itemName: String) throws {
        try secureStoreDefaults.deleteItem(itemName: itemName)
    }

    public func delete() throws {
        try keyManagerService.deleteKeys(name: "\(configuration.id)PrivateKey")
        try keyManagerService.deleteKeys(name: "\(configuration.id)PublicKey")
    }
}
