import Foundation
@testable import SecureStore
import Testing

extension UserDefaultsStore {

    static func makeWithMocks(userDefaults: UserDefaults = UserDefaults.standard) -> UserDefaultsStore {
        return UserDefaultsStore(userDefaults: userDefaults)
    }
}

@Suite
struct UserDefaultsStoreTests {
    @Test
    func saveItem() {
        let defaults = UserDefaults.standard
        let sut: UserDefaultsStore = .makeWithMocks()
        let itemName = UUID().uuidString
        sut.saveItem(encyptedItem: "EncryptedItem", itemName: itemName)

        guard let testString = defaults.string(forKey: itemName) else {
            Issue.record("cant find item name")
            return
        }

        #expect(testString == "EncryptedItem")
    }
    
    @Test
    func getItem() {
        let defaults = UserDefaults.standard
        let itemName = UUID().uuidString
        defaults.set("EncryptedItem", forKey: itemName)

        let sut: UserDefaultsStore = .makeWithMocks(userDefaults: defaults)
        let item = sut.getItem(itemName: itemName)

        #expect(item == "EncryptedItem")
    }
    
    @Test
    func deleteItem() {
        let defaults = UserDefaults.standard
        let itemName = UUID().uuidString
        defaults.set("EncryptedItem", forKey: itemName)

        let sut: UserDefaultsStore = .makeWithMocks(userDefaults: defaults)
        sut.deleteItem(itemName: itemName)

        #expect(defaults.string(forKey: itemName) == nil)
    }
}
