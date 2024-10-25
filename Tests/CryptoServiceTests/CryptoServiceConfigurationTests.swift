@testable import CryptoService
import Testing

struct CryptoConfigurationTests {
    @Test
    func configFlags_open() {
        let sut = CryptoServiceConfiguration(id: "test_id", accessControlLevel: .open)
        #expect(sut.accessControlLevel.flags == [])
    }
    
    @Test
    func configFlags_anyBiometricsOnly() {
        let sut = CryptoServiceConfiguration(id: "test_id", accessControlLevel: .anyBiometricsOnly)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .biometryAny])
    }
    
    @Test
    func configFlags_anyBiometricsOrPasscode() {
        let sut = CryptoServiceConfiguration(id: "test_id", accessControlLevel: .anyBiometricsOrPasscode)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .userPresence])
    }
    
    @Test
    func configFlags_currentBiometricsOnly() {
        let sut = CryptoServiceConfiguration(id: "test_id", accessControlLevel: .currentBiometricsOnly)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .biometryCurrentSet])
    }
    
    @Test
    func configFlags_currentBiometricsOrPasscode() {
        let sut = CryptoServiceConfiguration(id: "test_id", accessControlLevel: .currentBiometricsOrPasscode)
        #expect(sut.accessControlLevel.flags == [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode])
    }
}
