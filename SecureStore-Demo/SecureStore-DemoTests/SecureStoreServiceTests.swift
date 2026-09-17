@testable import SecureStore
import Testing

extension LocalAuthenticationLocalizedStrings {
    
    static func make(localizedReason: String = "Local Authentication Reason",
                     localisedFallbackTitle: String = "Enter passcode",
                     localisedCancelTitle: String = "Cancel") -> LocalAuthenticationLocalizedStrings {
    return LocalAuthenticationLocalizedStrings(
        localizedReason: localizedReason,
        localisedFallbackTitle: localisedFallbackTitle,
        localisedCancelTitle: localisedCancelTitle)
    }
}

extension SecureStoreService {
    static func make(localAuthStrings: LocalAuthenticationLocalizedStrings = .make()) -> SecureStoreService {
        return SecureStoreService(
            configuration: .init(
                id: "id",
                accessControlLevel: .open,
                localAuthStrings: localAuthStrings
            )
        )
    }
}

@Suite(.serialized)
struct SecureStoreServiceTests {
    
    @Test
    func test_keysCreatedOnInit() throws {
        let sut: SecureStoreService = .make()
        defer {
            sut.deleteItem(itemName: "ThisHere")
        }
        try sut.saveItem(item: "This", itemName: "ThisHere")
    }
    
    @Test
    func test_checkItemExists_itemExists() throws {
        let sut: SecureStoreService = .make()
        defer {
            sut.deleteItem(itemName: "ItemName")
        }
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        #expect(sut.checkItemExists(itemName: "ItemName"))
    }
    
    @Test
    func test_checkItemExists_itemDoesNotExists() {
        let sut: SecureStoreService = .make()
        #expect(sut.checkItemExists(itemName: "NewItemName") == false)
    }
    
    @Test
    func test_readItem_itemExists() throws {
        let sut: SecureStoreService = .make()
        defer {
            sut.deleteItem(itemName: "ItemName")
        }
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        #expect(try sut.readItem(itemName: "ItemName") == "ThisItem")
    }
    
    @Test
    func test_deleteItem() throws {
        let sut: SecureStoreService = .make()
        try sut.saveItem(item: "ThisItem", itemName: "ItemName")
        sut.deleteItem(itemName: "ThisItem")
        
        let error = #expect(throws: SecureStoreError.self, "cannot retrieve non-existent key") {
            _ = try sut.readItem(itemName: "ThisItem")
        }
        
        #expect(error?.kind == .unableToRetrieveFromUserDefaults)
    }
    
    @Test
    func test_saveItems_throwsError_whenNoKeysExist() throws {
        let sut: SecureStoreService = .make()
        try sut.delete()
        
        let error = #expect(throws: SecureStoreError.self, "cannot retrieve non-existent key") {
            try sut.saveItem(item: "", itemName: "")
        }
        
        #expect(error?.kind == .cantRetrieveKey)
    }
    
    @Test
    func test_storeKeys() throws {
        let sut: SecureStoreService = .make()
        try sut.keyManagerService.createKeysIfNeeded(name: "Test_Keys")

        #expect(throws: Never.self) {
            _ = try sut.keyManagerService.retrieveKeys()
        }
    }
    
    @Test
    func test_encryptDataWithPublicKey() throws {
        let sut: SecureStoreService = .make()
        try sut.keyManagerService.createKeysIfNeeded(name: "Test_Keys")
        
        #expect(throws: Never.self) {
            _ = try sut.keyManagerService.retrieveKeys()
            _ = try sut.keyManagerService.encryptDataWithPublicKey(dataToEncrypt: "This Data")
        }
    }
        
    @Test
    func test_decryptDataWithPrivateKey() throws {
        let sut: SecureStoreService = .make()
        try sut.keyManagerService.createKeysIfNeeded(name: "Test_Keys")
        
        #expect(throws: Never.self) {
            _ = try sut.keyManagerService.retrieveKeys()
        }
        
        let encryptedString = try sut.keyManagerService.encryptDataWithPublicKey(dataToEncrypt: "Data")
        
        #expect(throws: Never.self) {
            _ = try sut.keyManagerService
                .decryptDataWithPrivateKey(dataToDecrypt: encryptedString)
        }
    }
    
    @Test
    func testUsingEncryptorSaveCanReadItem() throws {
        let item = "any"
        let itemName = "any"
        
        let sut: EncryptedSecureStorable = SecureStoreService.make()
        
        defer {
            sut.deleteItem(itemName: itemName)
        }
        
        let encryptor = try sut.encryptor()
        
        try sut.save(using: encryptor, item: item, itemName: itemName)
        
        let actual = try sut.readItem(itemName: itemName)

        #expect(actual == item)
    }
}
