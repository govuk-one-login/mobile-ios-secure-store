@testable import CryptoService
import Foundation
import Testing

struct CryptoKeyStoreTests {
    let localAuthStrings: LocalAuthenticationLocalizedStrings
    let configuration: CryptographyServiceConfiguration
    let sut: CryptoKeyStore
    
    init() {
        localAuthStrings = LocalAuthenticationLocalizedStrings(
            localizedReason: "test_reason",
            localisedFallbackTitle: "test_fallback",
            localisedCancelTitle: "test_cancel"
        )
        configuration = CryptographyServiceConfiguration(
            id: "test_config",
            accessControlLevel: .open,
            localAuthStrings: localAuthStrings
        )
        sut = CryptoKeyStore(configuration: configuration)
    }
    
    @Test()
    func setup() {
        #expect(performing: {
            try sut.setup()
        }, throws: { error in
            (error as NSError).domain == NSOSStatusErrorDomain && (error as NSError).code == -34018
        })
    }
    
    @Test()
    func deleteKeys() {
        #expect(performing: {
            try sut.deleteKeys()
        }, throws: {
            $0 as? KeyPairAdministratorError == .cantDeleteKeys
        })
    }
}
