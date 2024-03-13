import XCTest
@testable import SecureStore

final class SecureStoreDemoTests: XCTestCase {
    var sut: SecureStoreService!

    override func setUp() {
        super.setUp()
        sut = SecureStoreService(configuration: .init(id: "id",
                                                      accessControlLevel: .open,
                                                      localAuthStrings: nil))
    }

    override func tearDown() {
        super.tearDown()
        sut = nil
    }
}

extension SecureStoreDemoTests {
    func test_keysCreatedOnInit() throws {
        try sut.saveItem(item: "This", itemName: "ThisHere")
    }

    func test_checkItemExists_itemExists() throws {
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        XCTAssertTrue(try sut.checkItemExists(itemName: "ItemName"))
    }

    func test_checkItemExists_itemDoesNotExists() throws {
        XCTAssertFalse(try sut.checkItemExists(itemName: "NewItemName"))
    }

    func test_readItem_itemExists() throws {
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        XCTAssertEqual(try sut.readItem(itemName: "ItemName"), "ThisItem")
    }

    func test_deleteItem() throws {
        let exp = expectation(description: "correct error hit")
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        try sut.deleteItem(itemName: "ThisItem")

        do {
            _ = try sut.readItem(itemName: "ThisItem")
        } catch let error as SecureStoreError where error == .unableToRetrieveFromUserDefaults {
            exp.fulfill()
        }

        wait(for: [exp], timeout: 3)
    }

    func test_deleteStore() throws {
        let exp = expectation(description: "correct error hit")
        try sut.delete()

        do {
            _ = try sut.saveItem(item: "", itemName: "")
        } catch let error as SecureStoreError where error == .cantRetrieveKey {
            exp.fulfill()
        }

        wait(for: [exp], timeout: 3)
    }

    func test_storeKeys() throws {
        do {
            try sut.keyManagerService.createKeysIfNeeded(name: "Test_Keys")
        } catch {
            print(error)
        }

        let publicKey = try sut.keyManagerService.retrievePublicKey()
        let privateKey = try sut.keyManagerService.retrievePrivateKey(localAuthStrings: nil)
        XCTAssertNotNil(publicKey)
        XCTAssertNotNil(privateKey)
    }

    func test_encryptDataWithPublicKey() throws {
        do {
            try sut.keyManagerService.createKeysIfNeeded(name: "Test_Keys")
        } catch {
            print(error)
        }

        let publicKey = try sut.keyManagerService.retrievePublicKey()
        let privateKey = try sut.keyManagerService.retrievePrivateKey(localAuthStrings: nil)
        XCTAssertNotNil(publicKey)
        XCTAssertNotNil(privateKey)

        let encryptedString = try sut.keyManagerService.encryptDataWithPublicKey(dataToEncrypt: "This Data")
        XCTAssertNotNil(encryptedString)
    }

    func test_decryptDataWithPrivateKey() throws {
        do {
            try sut.keyManagerService.createKeysIfNeeded(name: "Test_Keys")
        } catch {
            print(error)
        }

        let publicKey = try sut.keyManagerService.retrievePublicKey()
        let privateKey = try sut.keyManagerService.retrievePrivateKey(localAuthStrings: nil)
        XCTAssertNotNil(publicKey)
        XCTAssertNotNil(privateKey)

        guard let encryptedString = try sut.keyManagerService.encryptDataWithPublicKey(dataToEncrypt: "Data") else {
            XCTFail("Failed to encrypt string")
            return
        }

        let decryptedString = try sut.keyManagerService.decryptDataWithPrivateKey(dataToDecrypt: encryptedString, localAuthStrings: nil)
        XCTAssertNotNil(decryptedString)
    }
}
