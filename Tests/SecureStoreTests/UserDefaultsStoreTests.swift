@testable import SecureStore
import XCTest

final class UserDefaultsStoreTests: XCTestCase {
    var sut: DefaultsStore!
    let defaults = UserDefaults.standard

    override func setUp() {
        super.setUp()

        sut = UserDefaultsStore(userDefaults: defaults)
    }

    override func tearDown() {
        super.tearDown()
        sut = nil
    }
}

extension UserDefaultsStoreTests {
    func test_saveItem() throws {
        try sut.saveItem(encyptedItem: "EncryptedItem", itemName: "ItemName")

        guard let testString = defaults.string(forKey: "ItemName") else {
            XCTFail("cant find item name")
            return
        }

        XCTAssertEqual(testString, "EncryptedItem")
    }

    func test_getItem() throws {
        defaults.set("EncryptedItem", forKey: "ItemName")

        let item = try sut.getItem(itemName: "ItemName")

        XCTAssertEqual(item, "EncryptedItem")
    }

    func test_deleteItem() throws {
        defaults.set("EncryptedItem", forKey: "ItemName")

        try sut.deleteItem(itemName: "ItemName")

        if defaults.string(forKey: "ItemName") == nil {
            XCTFail("cant delete item")
            return
        }
    }
}
