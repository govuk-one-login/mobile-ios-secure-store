import LocalAuthentication
@testable import SecureStore
import XCTest


final class SecureStoreTests: XCTestCase {
    var sut: SecureStoreService!
    let mockDefaultsStore = MockDefaultsStore()

    override func setUp() {
        super.setUp()

        let config = SecureStorageConfiguration(id: "New_ID", accessControlLevel: .open)

        sut = SecureStoreService(keyManagerService: KeyManagerService(configuration: config),
                                 defaultsStore: mockDefaultsStore)
    }

    override func tearDown() {
        super.tearDown()
        sut = nil
    }
}

extension SecureStoreTests {
    func test_readItem() throws {
        _ = try sut.secureStoreDefaults.getItem(itemName: "ThisKey")
        XCTAssertTrue(mockDefaultsStore.didCallGetItem)
    }

    func test_deleteItem() throws {
        _ = try sut.secureStoreDefaults.deleteItem(itemName: "ThisKey")
        XCTAssertTrue(mockDefaultsStore.didCallDeleteItem)
    }

    func test_saveItem() throws {
        _ = try sut.secureStoreDefaults.saveItem(encyptedItem: "Item", itemName: "ThisKey")
        XCTAssertTrue(mockDefaultsStore.didCallSaveItem)
    }
}
