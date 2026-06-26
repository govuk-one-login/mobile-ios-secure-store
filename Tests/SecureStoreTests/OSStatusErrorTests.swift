import Foundation
@testable import SecureStore
import Security
import Testing

struct OSStatusErrorTests {

    @Test func makeKeyManagerServiceError() async throws {
        let anyStatus: OSStatus = errSecItemNotFound
        let error: OSStatusError = .make(status: anyStatus)
        
        #expect(OSStatusError.errorDomain == NSOSStatusErrorDomain)
        #expect(error.errorCode == anyStatus)
    }

    @Test func underLyingError() async throws {
        let anyStatus: OSStatus = errSecItemNotFound
        let anyError: NSError = .init(domain: "any", code: 1)
        let error: OSStatusError = .make(status: anyStatus, underlyingError: anyError)
        
        let actualUnderLyingError = try #require(error.errorUserInfo[NSUnderlyingErrorKey] as? NSError)
        #expect(actualUnderLyingError == anyError)
    }

    /// Asserts that the debugDescription, as it is computed by a GDSError (i.e. SecureStoreError),
    /// includes the debug description found in a non-GDSError that is instead a CustomNSError (i.e. KeyManagerServiceError)
    /// when the non-GDSError is the `originalError`.
    @Test
    func secureStoreErrorWithDebugDescriptionGivenOSStatusWithWithErrorMessageString() async throws {
        let errSecItemNotFound: OSStatus = errSecItemNotFound
        let errSecItemNotFoundDebugDescriptionExpected = "The specified item could not be found in the keychain."
        
        let error: OSStatusError = .make(status: errSecItemNotFound)
        let anySecureStoreError = SecureStoreError(.cantRetrieveKey, originalError: error)
        
        #expect(anySecureStoreError.debugDescription == "Error while retrieving key from the keychain - (\(errSecItemNotFoundDebugDescriptionExpected))")
    }
}
