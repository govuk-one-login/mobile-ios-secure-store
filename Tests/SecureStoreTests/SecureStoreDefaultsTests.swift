@testable import SecureStore
import XCTest

final class SecureStoreDefaultsTests: XCTestCase {
    var sut: SecureStoreDefaults!
    let defaults = UserDefaults.standard
    let mockSecureStore = MockSecureStore()
    
    override func setUp() {
        super.setUp()
        
        sut = SecureStoreUserDefaults(userDefaults: defaults)
    }
    
    override func tearDown() {
        super.tearDown()
        sut = nil
    }
}

extension SecureStoreDefaultsTests {
    func test_saveItem() throws {
        try sut.saveItem(encyptedItem: "This", itemName: "ItemName")
        
        guard let testString = defaults.string(forKey: "ItemName") else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(testString, "This")
    }
    
    func test_getItem() throws {
        defaults.set("This", forKey: "ItemName")
        
        let item = try sut.getItem(itemName: "ItemName")
        
        XCTAssertEqual(item, "This")
    }
    
    func test_deleteItem() throws {
        defaults.set("This", forKey: "ItemName")
        
        try sut.deleteItem(itemName: "ItemName")
        
        if let _ = defaults.string(forKey: "ItemName") {
            XCTFail()
            return
        }
    }
}
