import LocalAuthentication
@testable import SecureStore
import XCTest

final class SecureStoreTestsV2: XCTestCase {
    var mockDefaultsStore: MockDefaultsStore!
    var sut: SecureStoreServiceV2!
    
    override func setUp() {
        super.setUp()
        
        let config = SecureStorageConfiguration(
            id: "New_ID",
            accessControlLevel: .open
        )
        mockDefaultsStore = MockDefaultsStore()
        sut = SecureStoreServiceV2(
            keyManagerService: KeyManagerService(configuration: config),
            defaultsStore: mockDefaultsStore
        )
    }
    
    override func tearDown() {
        super.tearDown()
        
        mockDefaultsStore = nil
        sut = nil
    }
}

extension SecureStoreTestsV2 {
    func test_readItem() {
        _ = sut.secureStoreDefaults.getItem(itemName: "ThisKey")
        XCTAssertTrue(mockDefaultsStore.didCallGetItem)
    }
    
    func test_deleteItem() {
        _ = sut.secureStoreDefaults.deleteItem(itemName: "ThisKey")
        XCTAssertTrue(mockDefaultsStore.didCallDeleteItem)
    }
    
    func test_saveItem() {
        _ = sut.secureStoreDefaults.saveItem(encyptedItem: "Item", itemName: "ThisKey")
        XCTAssertTrue(mockDefaultsStore.didCallSaveItem)
    }
}
