@testable import SecureStore
import XCTest

final class SecureStoreDemoTests: XCTestCase {
    var testAuthStrings: LocalAuthenticationLocalizedStrings!
    var sut: SecureStoreService!
    
    override func setUp() {
        super.setUp()
        testAuthStrings = LocalAuthenticationLocalizedStrings(localizedReason: "Local Authentication Reason",
                                                              localisedFallbackTitle: "Enter passcode",
                                                              localisedCancelTitle: "Cancel")
        sut = SecureStoreService(configuration: .init(id: "id",
                                                      accessControlLevel: .open,
                                                      localAuthStrings: testAuthStrings))
    }
    
    override func tearDown() {
        super.tearDown()
        testAuthStrings = nil
        sut = nil
    }
}

extension SecureStoreDemoTests {
    func test_keysCreatedOnInit() throws {
        try sut.saveItem(item: "This", itemName: "ThisHere")
    }
    
    func test_checkItemExists_itemExists() throws {
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        XCTAssertTrue(sut.checkItemExists(itemName: "ItemName"))
    }
    
    func test_checkItemExists_itemDoesNotExists() {
        XCTAssertFalse(sut.checkItemExists(itemName: "NewItemName"))
    }
    
    func test_readItem_itemExists() throws {
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        XCTAssertEqual(try sut.readItem(itemName: "ItemName"), "ThisItem")
    }
    
    func test_deleteItem() throws {
        let exp = expectation(description: "correct error hit")
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        sut.deleteItem(itemName: "ThisItem")
        
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
            try sut.saveItem(item: "", itemName: "")
        } catch let error as SecureStoreError where error == .cantRetrieveKey {
            exp.fulfill()
        }
        
        wait(for: [exp], timeout: 3)
    }
    
    func test_storeKeys() throws {
        do {
            try sut.keyManagerService.createKeysIfNeeded()
        } catch {
            print(error)
        }
        
        let keys = try sut.keyManagerService.retrieveKeys()
        XCTAssertNotNil(keys.publicKey)
        XCTAssertNotNil(keys.privateKey)
    }
    
    func test_encryptDataWithPublicKey() throws {
        do {
            try sut.keyManagerService.createKeysIfNeeded()
        } catch {
            print(error)
        }
        
        let keys = try sut.keyManagerService.retrieveKeys()
        XCTAssertNotNil(keys.publicKey)
        
        let encryptedString = try sut.keyManagerService.encryptDataWithPublicKey(dataToEncrypt: "This Data")
        XCTAssertNotNil(encryptedString)
    }
    
    func test_decryptDataWithPrivateKey() throws {
        do {
            try sut.keyManagerService.createKeysIfNeeded()
        } catch {
            print(error)
        }
        
        let keys = try sut.keyManagerService.retrieveKeys()
        XCTAssertNotNil(keys.privateKey)
        
        let encryptedString = try sut.keyManagerService.encryptDataWithPublicKey(dataToEncrypt: "Data")
        
        let decryptedString = try sut.keyManagerService
            .decryptDataWithPrivateKey(dataToDecrypt: encryptedString)
        XCTAssertNotNil(decryptedString)
    }
}
