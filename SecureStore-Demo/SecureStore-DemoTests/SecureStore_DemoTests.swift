import XCTest
import SecureStore
@testable import SecureStore_Demo

final class SecureStore_DemoTests: XCTestCase {
    var sut: SecureStoreService!
    
    override func setUp() {
        super.setUp()
        sut = SecureStoreService(configuration: .init(id: "id", 
                                                      accessControlLevel: .open))
    }
    
    override func tearDown() {
        super.tearDown()
        sut = nil
    }
}

extension SecureStore_DemoTests {
    func test_keysCreatedOnInit() throws {
        try sut.saveItem(item: "This", itemName: "ThisHere")
    }
    
    
    func test_storeKeys() throws {
        do {
            try sut.createKeysIfNeeded(name: "Test_Keys")
        } catch {
            print(error)
        }
        
        let keys = try sut.retrieveKeys()
        XCTAssertNotNil(keys.publicKey)
        XCTAssertNotNil(keys.privateKey)
    }
    
    func test_encryptDataWithPublicKey() throws {
        do {
            try sut.createKeysIfNeeded(name: "Test_Keys")
        } catch {
            print(error)
        }
        
        let keys = try sut.retrieveKeys()
        XCTAssertNotNil(keys.publicKey)

        let encryptedString = try sut.encryptDataWithPublicKey(dataToEncrypt: "This Data")
        XCTAssertNotNil(encryptedString)
    }
    
    func test_decryptDataWithPrivateKey() throws {
        do {
            try sut.createKeysIfNeeded(name: "Test_Keys")
        } catch {
            print(error)
        }
        
        let keys = try sut.retrieveKeys()
        XCTAssertNotNil(keys.privateKey)
        
        guard let encryptedString = try sut.encryptDataWithPublicKey(dataToEncrypt: "This Data") else {
            XCTFail()
            return
        }

        let decryptedString = try sut.decryptDataWithPrivateKey(dataToDecrypt: encryptedString)
        XCTAssertNotNil(decryptedString)
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
            let _ = try sut.readItem(itemName: "ThisItem")
        } catch let error as SecureStoreError where error == .unableToRetrieveFromUserDefaults {
            exp.fulfill()
        }
        
        wait(for: [exp], timeout: 3)
    }
    
    func test_deleteStore() throws {
        let exp = expectation(description: "correct error hit")
        try sut.delete()
        
        do {
            let _ = try sut.retrieveKeys()
        } catch let error as SecureStoreError where error == .cantRetrieveKey {
            exp.fulfill()
        }
        
        wait(for: [exp], timeout: 3)
    }
    
//    func test_storeKeysL() throws {
//        guard let key = try generateTestKey() else {
//            XCTFail()
//            return
//        }
//        
//        try sut.storeKeys(keyToStore: key, name: "TestKeyPrivateKey")
//        
//        let keys = try sut.retrieveKeys()
//        XCTAssertEqual(keys.publicKey, key)
//    }
//
//    private func generateTestKey() throws -> SecKey? {
//        let name = "TestKeyPrivateKey"
//        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//                                                           kSecAttrAccessibleWhenUnlocked,
//                                                           [],
//                                                           nil),
//        let tag = name.data(using: .utf8) else { return nil }
//        
//        let attributes: NSDictionary = [
//            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
//            kSecAttrKeySizeInBits: 256,
//            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
//            kSecPrivateKeyAttrs: [
//                kSecAttrIsPermanent: true,
//                kSecAttrApplicationTag: tag,
//                kSecAttrAccessControl: access
//            ]
//        ]
//        
//        var error: Unmanaged<CFError>?
//        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
//            guard let error = error?.takeRetainedValue() as? Error else {
//                throw SecureStoreError.cantEncryptData
//            }
//            throw error
//        }
//        return privateKey
//    }
}
