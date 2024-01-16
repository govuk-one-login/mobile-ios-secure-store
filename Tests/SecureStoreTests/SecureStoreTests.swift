import JWTDecode
@testable import SecureStore
import XCTest

final class SecureStoreTests: XCTestCase {
    var sut: KeychainService!

    override func setUp() {
        super.setUp()
        sut = KeychainService(id: "key")
    }

    override func tearDown() {
        super.tearDown()
        sut = nil
    }
}
