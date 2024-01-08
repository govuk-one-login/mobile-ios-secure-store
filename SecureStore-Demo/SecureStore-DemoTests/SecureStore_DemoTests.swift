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
}
