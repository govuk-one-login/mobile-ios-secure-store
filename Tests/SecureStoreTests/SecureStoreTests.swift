import LocalAuthentication
@testable import SecureStore
import Testing

extension SecureStoreService {
    static func makeWithMocks(defaultsStore: DefaultsStore) -> SecureStoreService {
        
        let config = SecureStorageConfiguration(
            id: "New_ID",
            accessControlLevel: .open
        )

        return SecureStoreService(
            keyManagerService: KeyManagerService(configuration: config),
            defaultsStore: defaultsStore
        )
    }
}

struct SecureStoreTests {
    @Test
    func readItem() {
        let mockDefaultsStore = MockDefaultsStore()
        let sut: SecureStoreService = .makeWithMocks(defaultsStore: mockDefaultsStore)

        _ = sut.secureStoreDefaults.getItem(itemName: "ThisKey")

        #expect(mockDefaultsStore.didCallGetItem)
    }
    
    @Test
    func deleteItem() {
        let mockDefaultsStore = MockDefaultsStore()
        let sut: SecureStoreService = .makeWithMocks(defaultsStore: mockDefaultsStore)

        _ = sut.secureStoreDefaults.deleteItem(itemName: "ThisKey")

        #expect(mockDefaultsStore.didCallDeleteItem)
    }
    
    @Test
    func saveItem() {
        let mockDefaultsStore = MockDefaultsStore()
        let sut: SecureStoreService = .makeWithMocks(defaultsStore: mockDefaultsStore)

        _ = sut.secureStoreDefaults.saveItem(encyptedItem: "Item", itemName: "ThisKey")

        #expect(mockDefaultsStore.didCallSaveItem)
    }
}
