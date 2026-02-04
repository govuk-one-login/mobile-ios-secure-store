import GDSUtilities
import LocalAuthentication
@testable import SecureStore
import XCTest

final class SecureStoreErrorV2Tests: XCTestCase {
    func test_noError() {
        let error = SecureStoreErrorV2.biometricErrorHandling(
            error: nil
        )
        XCTAssertEqual(
            error,
            SecureStoreErrorV2(.noResultOrError)
        )
    }
    
    func test_cantDecryptDataError() {
        let cantDecryptDataError = NSError(
            domain: NSOSStatusErrorDomain,
            code: -50
        )
        let error = SecureStoreErrorV2.biometricErrorHandling(
            error: cantDecryptDataError
        )
        XCTAssertEqual(
            error.kind,
            .cantDecryptData
        )
        XCTAssertEqual(
            error.originalError as? NSError,
            cantDecryptDataError
        )
    }
    
    func test_unknownNSError() {
        let statusError = NSError(
            domain: NSOSStatusErrorDomain,
            code: -100
        )
        let error = SecureStoreErrorV2.biometricErrorHandling(
            error: statusError
        )
        XCTAssertEqual(
            error.kind,
            .unknownNSError
        )
        XCTAssertEqual(
            error.originalError as? NSError,
            statusError
        )
    }
    
    func test_authenticationFailedError() {
        let authenticationFailedError = LAError(.authenticationFailed) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: authenticationFailedError
            ),
            SecureStoreErrorV2(.authenticationFailed)
        )
    }
    
    func test_userCancelError() {
        let userCancelError = LAError(.userCancel) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: userCancelError
            ),
            SecureStoreErrorV2(.userCancel)
        )
    }
    
    func test_userFallbackErrorError() {
        let userFallbackError = LAError(.userFallback) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: userFallbackError
            ),
            SecureStoreErrorV2(.userFallback)
        )
    }
    
    func test_systemCancelError() {
        let systemCancelError = LAError(.systemCancel) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: systemCancelError
            ),
            SecureStoreErrorV2(.systemCancel)
        )
    }
    
    func test_passcodeNotSetError() {
        let noPasscodeSetError = LAError(.passcodeNotSet) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: noPasscodeSetError
            ),
            SecureStoreErrorV2(.passcodeNotSet)
        )
    }
    
    func test_biometryNotAvailableError() {
        let biometryNotAvailableError = LAError(.biometryNotAvailable) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryNotAvailableError
            ),
            SecureStoreErrorV2(.biometryNotAvailable)
        )
    }
    
    func test_biometryNotEnrolledError() {
        let biometryNotEnrolledError = LAError(.biometryNotEnrolled) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryNotEnrolledError
            ),
            SecureStoreErrorV2(.biometryNotEnrolled)
        )
    }
    
    func test_biometryLockoutError() {
        let biometryLockoutError = LAError(.biometryLockout) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryLockoutError
            ),
            SecureStoreErrorV2(.biometryLockout)
        )
    }
    
    func test_appCancelError() {
        let appCancelError = LAError(.appCancel) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: appCancelError
            ),
            SecureStoreErrorV2(.appCancel)
        )
    }
    
    func test_invalidContextError() {
        let invalidContextError = LAError(.invalidContext) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: invalidContextError
            ),
            SecureStoreErrorV2(.invalidContext)
        )
    }
    
    @available(macOS 15.0, *)
    @available(iOS 18.0, *)
    func test_companionNotAvailableError() {
        let companionNotAvailableError = LAError(.companionNotAvailable) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: companionNotAvailableError
            ),
            SecureStoreErrorV2(.companionNotAvailable)
        )
    }
    
    #if os(macOS)
    func test_biometryNotPairedError() {
        let biometryNotPairedError = LAError(.biometryNotPaired) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryNotPairedError
            ),
            SecureStoreErrorV2(.biometryNotPaired)
        )
    }
    
    func test_biometryDisconnectedError() {
        let biometryDisconnectedError = LAError(.biometryDisconnected) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: biometryDisconnectedError
            ),
            SecureStoreErrorV2(.biometryDisconnected)
        )
    }
    
    func test_invalidDimensionsError() {
        let invalidDimensionsError = LAError(.invalidDimensions) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: invalidDimensionsError
            ),
            SecureStoreErrorV2(.invalidDimensions)
        )
    }
    #endif
    
    func test_notInteractiveError() {
        let notInteractiveError = LAError(.notInteractive) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: notInteractiveError
            ),
            SecureStoreErrorV2(.notInteractive)
        )
    }
    
    func test_invalidatedByHandleRequestError() throws {
        let invalidatedByHandleRequestError = LAError(try XCTUnwrap(LAError.Code(rawValue: 4))) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: invalidatedByHandleRequestError
            ),
            SecureStoreErrorV2(.invalidatedByHandleRequest)
        )
    }
    
    func test_viewServiceInitializationFailureError() throws {
        let viewServiceInitializationFailureError = LAError(try XCTUnwrap(LAError.Code(rawValue: 6))) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: viewServiceInitializationFailureError
            ),
            SecureStoreErrorV2(.viewServiceInitializationFailure)
        )
    }
    
    func test_authenticationTimedOutError() throws {
        let authenticationTimedOutError = LAError(try XCTUnwrap(LAError.Code(rawValue: -1000))) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: authenticationTimedOutError
            ),
            SecureStoreErrorV2(.authenticationTimedOut)
        )
    }
    
    func test_uiActivationTimedOutError() throws {
        let uiActivationTimedOutError = LAError(try XCTUnwrap(LAError.Code(rawValue: -1003))) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: uiActivationTimedOutError
            ),
            SecureStoreErrorV2(.uiActivationTimedOut)
        )
    }
    
    func test_unknownLAError() throws {
        let unknownLAError = LAError(try XCTUnwrap(LAError.Code(rawValue: -999))) as NSError
        XCTAssertEqual(
            SecureStoreErrorV2.biometricErrorHandling(
                error: unknownLAError
            ),
            SecureStoreErrorV2(.unknownLAError)
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
        XCTAssertEqual(SecureStoreErrorV2(.cantEncodeData).reason,
                       "Error while encoding data")
        XCTAssertEqual(SecureStoreErrorV2(.cantDecodeData).reason,
                       "Error while decoding data")
        XCTAssertEqual(SecureStoreErrorV2(.cantFormatData).reason,
                       "Error while formatting data")
        XCTAssertEqual(SecureStoreErrorV2(.authenticationFailed).reason,
                       "User failed to provide valid credentials")
        XCTAssertEqual(SecureStoreErrorV2(.userCancel).reason,
                       "User cancelled the biometric prompt")
        XCTAssertEqual(SecureStoreErrorV2(.userFallback).reason,
                       "No fallback is available for the authentication policy")
        XCTAssertEqual(SecureStoreErrorV2(.systemCancel).reason,
                       "System cancelled authentication")
        XCTAssertEqual(SecureStoreErrorV2(.passcodeNotSet).reason,
                       "A passcode isn't set on the device")
        XCTAssertEqual(SecureStoreErrorV2(.biometryNotAvailable).reason,
                       "No biometry available on the device")
        XCTAssertEqual(SecureStoreErrorV2(.biometryNotEnrolled).reason,
                       "Biometry is not enrolled on the device")
        XCTAssertEqual(SecureStoreErrorV2(.biometryLockout).reason,
                       "Biometry is locked out")
        XCTAssertEqual(SecureStoreErrorV2(.appCancel).reason,
                       "App cancelled authentication")
        XCTAssertEqual(SecureStoreErrorV2(.invalidContext).reason,
                       "The context was previously invalidated")
        XCTAssertEqual(SecureStoreErrorV2(.companionNotAvailable).reason,
                       "No paired companion device nearby")
        #if os(macOS)
        XCTAssertEqual(SecureStoreErrorV2(.biometryNotPaired).reason,
                       "Device supports biometry only via removable accessories and no accessory has been paired")
        XCTAssertEqual(SecureStoreErrorV2(.biometryDisconnected).reason,
                       "Device supports biometry only via removable accessories and the paired accessory is not connected.")
        XCTAssertEqual(SecureStoreErrorV2(.invalidDimensions).reason,
                       "Dimensions of embedded UI are invalid")
        #endif
        XCTAssertEqual(SecureStoreErrorV2(.notInteractive).reason,
                       "Displaying the required authentication user interface is forbidden")
        XCTAssertEqual(SecureStoreErrorV2(.invalidatedByHandleRequest).reason,
                       "Invalidated by handle request")
        XCTAssertEqual(SecureStoreErrorV2(.viewServiceInitializationFailure).reason,
                       "Invalidated due to view service initialization failure")
        XCTAssertEqual(SecureStoreErrorV2(.authenticationTimedOut).reason,
                       "Authentication timed out")
        XCTAssertEqual(SecureStoreErrorV2(.uiActivationTimedOut).reason,
                       "UI activation timed out after 5 seconds")
        XCTAssertEqual(SecureStoreErrorV2(.unknownLAError).reason,
                       "Unknown LAError")
        XCTAssertEqual(SecureStoreErrorV2(.unknownNSError).reason,
                       "Unknow NSError")
        XCTAssertEqual(SecureStoreErrorV2(.noResultOrError).reason,
                       "No result or error returned")
    }
}
