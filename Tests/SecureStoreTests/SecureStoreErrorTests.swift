import GDSUtilities
import LocalAuthentication
@testable import SecureStore
import XCTest

final class SecureStoreErrorTests: XCTestCase {
    func test_error_reason() {
        XCTAssertEqual(SecureStoreError(.unableToRetrieveFromUserDefaults).reason,
                       "Error while retrieving item from User Defaults")
        XCTAssertEqual(SecureStoreError(.cantDeleteKey).reason,
                       "Error while deleting key from the keychain")
        XCTAssertEqual(SecureStoreError(.cantStoreKey).reason,
                       "Error while storing key to the keychain")
        XCTAssertEqual(SecureStoreError(.cantRetrieveKey).reason,
                       "Error while retrieving key from the keychain")
        XCTAssertEqual(SecureStoreError(.cantEncryptData).reason,
                       "Error while encrypting data")
        XCTAssertEqual(SecureStoreError(.cantDecryptData).reason,
                       "Error while decrypting data")
        XCTAssertEqual(SecureStoreError(.userCancelled).reason,
                       "User cancelled the biometric prompt")
        XCTAssertEqual(SecureStoreError(.cantEncodeData).reason,
                       "Error while encoding data")
        XCTAssertEqual(SecureStoreError(.cantDecodeData).reason,
                       "Error while decoding data")
        XCTAssertEqual(SecureStoreError(.cantFormatData).reason,
                       "Error while formatting data")
    }
    
    func test_secureStoreError_errorReasonReturnsNil() {
        enum TestErrorKind: String, GDSErrorKind, CaseIterable {
            case errorKindWithNoReason
        }
        
        XCTAssertEqual(GDSSecureStoreError(TestErrorKind.errorKindWithNoReason).reason, nil)
    }
    
    // swiftlint:disable function_body_length
    func test_localAuthenticationErrors_recoverable() {
        let authenticationFailedError = CFErrorCreate(nil, LAErrorDomain as CFString, -1, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: authenticationFailedError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let userFallbackError = CFErrorCreate(nil, LAErrorDomain as CFString, -3, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: userFallbackError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        
        let systemCancelError = CFErrorCreate(nil, LAErrorDomain as CFString, -4, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: systemCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let appCancelError = CFErrorCreate(nil, LAErrorDomain as CFString, -9, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: appCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let invalidContextError = CFErrorCreate(nil, LAErrorDomain as CFString, -10, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: invalidContextError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let biometryNotAvailableError = CFErrorCreate(nil, LAErrorDomain as CFString, LAError.biometryNotAvailable.rawValue, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: biometryNotAvailableError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let biometryNotEnrolledError = CFErrorCreate(nil, LAErrorDomain as CFString, LAError.biometryNotEnrolled.rawValue, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: biometryNotEnrolledError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let biometryLockoutError = CFErrorCreate(nil, LAErrorDomain as CFString, LAError.biometryLockout.rawValue, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: biometryLockoutError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let notInteractiveError = CFErrorCreate(nil, LAErrorDomain as CFString, -1004, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: notInteractiveError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )

        let backgroundError = CFErrorCreate(nil, LAErrorDomain as CFString, 6, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: backgroundError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let uiError = CFErrorCreate(nil, LAErrorDomain as CFString, -1000, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: uiError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
    }
    // swiftlint:enable function_body_length
    
    func test_localAuthenticationErrors_userCancelled() {
        let userCancelError = CFErrorCreate(nil, LAErrorDomain as CFString, -2, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: userCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.userCancelled)
        )
    }
    
    func test_localAuthenticationErrors_unrecoverable() {
        let statusError = CFErrorCreate(nil, NSOSStatusErrorDomain as CFString, -50, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: statusError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.unrecoverable)
        )
    }
    
    func test_localAuthenticationErrors_noLocalAuthEnrolled() {
        let noPasscodeSetError = CFErrorCreate(nil, LAErrorDomain as CFString, -5, nil)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: noPasscodeSetError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.noLocalAuthEnrolled)
        )
    }
}
