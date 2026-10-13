import LocalAuthentication
@testable import SecureStore
import Testing

struct SecureStoreConfigurationTests {
    
    @Test
    func configFlags_open() {
        let sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .open)
        #expect(sut.accessControlLevel.flags == [])
    }
    
    @Test
    func configFlags_anyBiometricsOnly() {
        let sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .anyBiometricsOnly)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .biometryAny])
    }
    
    @Test
    func configFlags_anyBiometricsOrPasscode() {
        let sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .anyBiometricsOrPasscode)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .userPresence])
    }
    
    @Test
    func configFlags_currentBiometricsOnly() {
        let sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .currentBiometricsOnly)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .biometryCurrentSet])
    }
    
    @Test
    func configFlags_currentBiometricsOrPasscode() {
        let sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .currentBiometricsOrPasscode)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode])
    }

    @Test
    func localAuthStringsProvider() throws {
        let localAuthStrings = LocalAuthenticationLocalizedStrings(localizedReason: "reason",
                                                                   localisedFallbackTitle: "fallbackTitle",
                                                                   localisedCancelTitle: "cancelTitle")
        let sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .open, localAuthStringsProvider: {
            return localAuthStrings
        })

        let expected: LocalAuthenticationLocalizedStrings = LocalAuthenticationLocalizedStrings(
            localizedReason: "reason",
            localisedFallbackTitle: "fallbackTitle",
            localisedCancelTitle: "cancelTitle"
        )

        #expect(try sut.localAuthStringsProvider() == expected)
    }
}
