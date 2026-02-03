import GDSUtilities
import LocalAuthentication
@testable import SecureStore
import XCTest

final class SecureStoreErrorV2Tests: XCTestCase {
    func test_unknownError() {
        let statusError = NSError(
            domain: NSOSStatusErrorDomain,
            code: -100
        )
        let error = SecureStoreErrorV2.biometricErrorHandling(
            error: statusError,
            defaultError: SecureStoreErrorV2(.cantEncryptData)
        )
        XCTAssertEqual(
            error as NSError,
            statusError
        )
    }
    
    func test_default() {
        let error = SecureStoreErrorV2.biometricErrorHandling(
            error: nil,
            defaultError: SecureStoreErrorV2(.cantEncryptData)
        )
        XCTAssertEqual(
            error as? SecureStoreErrorV2,
            SecureStoreErrorV2(.cantEncryptData)
        )
    }
    
    func test_nsosstatusError() {
        let statusError = NSError(domain: NSOSStatusErrorDomain, code: -50)
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: statusError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.unrecoverable)
        )
    }
    
    func test_userCancelError() {
        let userCancelError = LAError(.userCancel) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: userCancelError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.userCancelled)
        )
    }
    
    func test_noPasscodeSetError() {
        let noPasscodeSetError = LAError(.passcodeNotSet) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: noPasscodeSetError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.noLocalAuthEnrolled)
        )
    }
    
    func test_authenticationFailedError() {
        let authenticationFailedError = LAError(.authenticationFailed) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: authenticationFailedError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_userFallbackErrorError() {
        let userFallbackError = LAError(.userFallback) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: userFallbackError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_systemCancelError() {
        let systemCancelError = LAError(.systemCancel) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: systemCancelError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_appCancelError() {
        let appCancelError = LAError(.appCancel) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: appCancelError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_invalidContextError() {
        let invalidContextError = LAError(.invalidContext) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: invalidContextError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_biometryNotAvailableError() {
        let biometryNotAvailableError = LAError(.biometryNotAvailable) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryNotAvailableError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_biometryNotEnrolledError() {
        let biometryNotEnrolledError = LAError(.biometryNotEnrolled) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryNotEnrolledError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_biometryLockoutError() {
        let biometryLockoutError = LAError(.biometryLockout) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryLockoutError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_notInteractiveError() {
        let notInteractiveError = LAError(.notInteractive) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: notInteractiveError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_backgroundError() {
        let backgroundError = LAError(LAError.Code(rawValue: 6)!) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: backgroundError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_uiError() {
        let uiError = LAError(LAError.Code(rawValue: -1000)!) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: uiError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? SecureStoreErrorV2,
            SecureStoreErrorV2(.recoverable)
        )
    }
    
    func test_unknownLAError() {
        let uiError = LAError(LAError.Code(rawValue: -999)!) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: uiError,
                defaultError: SecureStoreErrorV2(.cantEncryptData)
            ) as? LAError,
            LAError(LAError.Code(rawValue: -999)!)
        )
    }
    
    func test_secureStoreError_errorReasonReturnsNil() {
        enum TestErrorKind: String, GDSErrorKind, CaseIterable {
            case errorKindWithNoReason
        }
        
        XCTAssertEqual(GDSSecureStoreError(TestErrorKind.errorKindWithNoReason).reason, nil)
    }
    
    func test_error_reason() {
        XCTAssertEqual(SecureStoreErrorV2(.unableToRetrieveFromUserDefaults).reason,
                       "Error while retrieving item from User Defaults")
        XCTAssertEqual(SecureStoreErrorV2(.cantDeleteKey).reason,
                       "Error while deleting key from the keychain")
        XCTAssertEqual(SecureStoreErrorV2(.cantStoreKey).reason,
                       "Error while storing key to the keychain")
        XCTAssertEqual(SecureStoreErrorV2(.cantRetrieveKey).reason,
                       "Error while retrieving key from the keychain")
        XCTAssertEqual(SecureStoreErrorV2(.cantEncryptData).reason,
                       "Error while encrypting data")
        XCTAssertEqual(SecureStoreErrorV2(.cantDecryptData).reason,
                       "Error while decrypting data")
        XCTAssertEqual(SecureStoreErrorV2(.userCancelled).reason,
                       "User cancelled the biometric prompt")
        XCTAssertEqual(SecureStoreErrorV2(.cantEncodeData).reason,
                       "Error while encoding data")
        XCTAssertEqual(SecureStoreErrorV2(.cantDecodeData).reason,
                       "Error while decoding data")
        XCTAssertEqual(SecureStoreErrorV2(.cantFormatData).reason,
                       "Error while formatting data")
    }
}
