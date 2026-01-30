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
        let authenticationFailedError = LAError(.authenticationFailed) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: authenticationFailedError,
                defaultError: SecureStoreError(.cantEncryptData)
            ) as? SecureStoreError,
            SecureStoreError(.recoverable)
        )

        let userFallbackError = LAError(.userFallback) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: userFallbackError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let systemCancelError = LAError(.systemCancel) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: systemCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let appCancelError = LAError(.appCancel) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: appCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let invalidContextError = LAError(.invalidContext) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: invalidContextError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let biometryNotAvailableError = LAError(.biometryNotAvailable) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: biometryNotAvailableError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let biometryNotEnrolledError = LAError(.biometryNotEnrolled) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: biometryNotEnrolledError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let biometryLockoutError = LAError(.biometryLockout) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: biometryLockoutError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let notInteractiveError = LAError(.notInteractive) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: notInteractiveError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )

        let backgroundError = LAError(LAError.Code(rawValue: 6)!) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: backgroundError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
        
        let uiError = LAError(LAError.Code(rawValue: -1000)!) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: uiError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.recoverable)
        )
    }
    // swiftlint:enable function_body_length
    
    func test_localAuthenticationErrors_userCancelled() {
        let userCancelError = LAError(.userCancel) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: userCancelError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.userCancelled)
        )
    }
    
    func test_localAuthenticationErrors_unrecoverable() {
        let statusError = NSError(domain: NSOSStatusErrorDomain, code: -50)
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: statusError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.unrecoverable)
        )
    }
    
    func test_localAuthenticationErrors_noLocalAuthEnrolled() {
        let noPasscodeSetError = LAError(.passcodeNotSet) as NSError
        XCTAssertEqual(SecureStoreError.biometricErrorHandling(
            error: noPasscodeSetError,
            defaultError: SecureStoreError(.cantEncryptData)
        ) as? SecureStoreError,
                       SecureStoreError(.noLocalAuthEnrolled)
        )
    }
}
