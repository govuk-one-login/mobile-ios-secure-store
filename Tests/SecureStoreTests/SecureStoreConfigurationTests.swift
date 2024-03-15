@testable import SecureStore
import XCTest
import LocalAuthentication

final class SecureStoreConfigurationTests: XCTestCase {
    var sut: SecureStorageConfiguration!

    func test_configFlags_open() throws {
        sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .open)
        XCTAssertEqual(sut.accessControlLevel.flags, [])
    }

    func test_configFlags_anyBiometricsOnly() throws {
        sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .anyBiometricsOnly)
        XCTAssertEqual(sut.accessControlLevel.flags, [.privateKeyUsage, .biometryAny])
    }

    func test_configFlags_anyBiometricsOrPasscode() throws {
        sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .anyBiometricsOrPasscode)
        XCTAssertEqual(sut.accessControlLevel.flags, [.privateKeyUsage, .biometryAny])
    }

    func test_configFlags_currentBiometricsOnly() throws {
        sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .currentBiometricsOnly)
        XCTAssertEqual(sut.accessControlLevel.flags, [.privateKeyUsage, .biometryCurrentSet])
    }

    func test_configFlags_currentBiometricsOrPasscode() throws {
        sut = SecureStorageConfiguration(id: "test_id", accessControlLevel: .currentBiometricsOrPasscode)
        XCTAssertEqual(sut.accessControlLevel.flags, [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode])
    }
}
