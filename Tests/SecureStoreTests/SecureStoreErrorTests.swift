// swiftlint:disable file_length
import GDSUtilities
import LocalAuthentication
@testable import SecureStore
import Testing
import XCTest

// swiftlint:disable:next type_body_length
final class SecureStoreErrorXCTests: XCTestCase {
    func test_noError() {
        let error = SecureStoreError.biometricErrorHandling(
            error: nil
        )
        XCTAssertEqual(
            error,
            SecureStoreError(.noResultOrError)
        )
    }
    
    func test_cantDecryptDataError() {
        let cantDecryptDataError = NSError(
            domain: NSOSStatusErrorDomain,
            code: -50
        )
        let error = SecureStoreError.biometricErrorHandling(
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
        let error = SecureStoreError.biometricErrorHandling(
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
            SecureStoreError.biometricErrorHandling(
                error: authenticationFailedError
            ),
            SecureStoreError(.authenticationFailed)
        )
    }
    
    func test_userCancelError() {
        let userCancelError = LAError(.userCancel) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: userCancelError
            ),
            SecureStoreError(.userCancel)
        )
    }
    
    func test_userFallbackErrorError() {
        let userFallbackError = LAError(.userFallback) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: userFallbackError
            ),
            SecureStoreError(.userFallback)
        )
    }
    
    func test_systemCancelError() {
        let systemCancelError = LAError(.systemCancel) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: systemCancelError
            ),
            SecureStoreError(.systemCancel)
        )
    }
    
    func test_passcodeNotSetError() {
        let noPasscodeSetError = LAError(.passcodeNotSet) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: noPasscodeSetError
            ),
            SecureStoreError(.passcodeNotSet)
        )
    }
    
    func test_biometryNotAvailableError() {
        let biometryNotAvailableError = LAError(.biometryNotAvailable) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: biometryNotAvailableError
            ),
            SecureStoreError(.biometryNotAvailable)
        )
    }
    
    func test_biometryNotEnrolledError() {
        let biometryNotEnrolledError = LAError(.biometryNotEnrolled) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: biometryNotEnrolledError
            ),
            SecureStoreError(.biometryNotEnrolled)
        )
    }
    
    func test_biometryLockoutError() {
        let biometryLockoutError = LAError(.biometryLockout) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: biometryLockoutError
            ),
            SecureStoreError(.biometryLockout)
        )
    }
    
    func test_appCancelError() {
        let appCancelError = LAError(.appCancel) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: appCancelError
            ),
            SecureStoreError(.appCancel)
        )
    }
    
    func test_invalidContextError() {
        let invalidContextError = LAError(.invalidContext) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: invalidContextError
            ),
            SecureStoreError(.invalidContext)
        )
    }
    
    @available(macOS 15.0, *)
    @available(iOS 18.0, *)
    func test_companionNotAvailableError() {
        let companionNotAvailableError = LAError(.companionNotAvailable) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: companionNotAvailableError
            ),
            SecureStoreError(.companionNotAvailable)
        )
    }
    
    #if os(macOS)
    func test_watchNotAvailableError() {
        let watchNotAvailableError = LAError(.watchNotAvailable) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: watchNotAvailableError
            ),
            SecureStoreError(.watchNotAvailable)
        )
    }
    func test_biometryNotPairedError() {
        let biometryNotPairedError = LAError(.biometryNotPaired) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: biometryNotPairedError
            ),
            SecureStoreError(.biometryNotPaired)
        )
    }
    
    func test_biometryDisconnectedError() {
        let biometryDisconnectedError = LAError(.biometryDisconnected) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: biometryDisconnectedError
            ),
            SecureStoreError(.biometryDisconnected)
        )
    }
    
    func test_invalidDimensionsError() {
        let invalidDimensionsError = LAError(.invalidDimensions) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: invalidDimensionsError
            ),
            SecureStoreError(.invalidDimensions)
        )
    }
    #endif
    
    func test_notInteractiveError() {
        let notInteractiveError = LAError(.notInteractive) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: notInteractiveError
            ),
            SecureStoreError(.notInteractive)
        )
    }
    
    func test_invalidatedByHandleRequestError() throws {
        let invalidatedByHandleRequestError = LAError(try XCTUnwrap(LAError.Code(rawValue: 4))) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: invalidatedByHandleRequestError
            ),
            SecureStoreError(.invalidatedByHandleRequest)
        )
    }
    
    func test_viewServiceInitializationFailureError() throws {
        let viewServiceInitializationFailureError = LAError(try XCTUnwrap(LAError.Code(rawValue: 6))) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: viewServiceInitializationFailureError
            ),
            SecureStoreError(.viewServiceInitializationFailure)
        )
    }
    
    func test_uiActivationTimedOutError() throws {
        let uiActivationTimedOutError = LAError(try XCTUnwrap(LAError.Code(rawValue: -1000))) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: uiActivationTimedOutError
            ),
            SecureStoreError(.uiActivationTimedOut)
        )
    }
    
    func test_authenticationTimedOutError() throws {
        let authenticationTimedOutError = LAError(try XCTUnwrap(LAError.Code(rawValue: -1003))) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: authenticationTimedOutError
            ),
            SecureStoreError(.authenticationTimedOut)
        )
    }
    
    func test_unknownLAError() throws {
        let unknownLAError = LAError(try XCTUnwrap(LAError.Code(rawValue: -999))) as NSError
        XCTAssertEqual(
            SecureStoreError.biometricErrorHandling(
                error: unknownLAError
            ),
            SecureStoreError(.unknownLAError)
        )
    }
    
    func test_secureStoreError_errorReasonReturnsNil() {
        enum TestErrorKind: Int, GDSErrorKind {
            case errorKindWithNoReason = 1
            
            var description: String {
                "errorKindWithNoReason"
            }
        }
        
        XCTAssertEqual(GDSSecureStoreError(TestErrorKind.errorKindWithNoReason).reason, nil)
    }
    
    // swiftlint:disable:next function_body_length
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
        XCTAssertEqual(SecureStoreError(.cantEncodeData).reason,
                       "Error while encoding data")
        XCTAssertEqual(SecureStoreError(.cantDecodeData).reason,
                       "Error while decoding data")
        XCTAssertEqual(SecureStoreError(.cantFormatData).reason,
                       "Error while formatting data")
        XCTAssertEqual(SecureStoreError(.authenticationFailed).reason,
                       "User failed to provide valid credentials")
        XCTAssertEqual(SecureStoreError(.userCancel).reason,
                       "User cancelled the biometric prompt")
        XCTAssertEqual(SecureStoreError(.userFallback).reason,
                       "No fallback is available for the authentication policy")
        XCTAssertEqual(SecureStoreError(.systemCancel).reason,
                       "System cancelled authentication")
        XCTAssertEqual(SecureStoreError(.passcodeNotSet).reason,
                       "A passcode isn't set on the device")
        XCTAssertEqual(SecureStoreError(.biometryNotAvailable).reason,
                       "No biometry available on the device")
        XCTAssertEqual(SecureStoreError(.biometryNotEnrolled).reason,
                       "Biometry is not enrolled on the device")
        XCTAssertEqual(SecureStoreError(.biometryLockout).reason,
                       "Biometry is locked out")
        XCTAssertEqual(SecureStoreError(.appCancel).reason,
                       "App cancelled authentication")
        XCTAssertEqual(SecureStoreError(.invalidContext).reason,
                       "The context was previously invalidated")
        XCTAssertEqual(SecureStoreError(.companionNotAvailable).reason,
                       "No paired companion device nearby")
        #if os(macOS)
        XCTAssertEqual(SecureStoreError(.watchNotAvailable).reason,
                       "No paired watch nearby")
        XCTAssertEqual(SecureStoreError(.biometryNotPaired).reason,
                       "Device supports biometry only via removable accessories and no accessory has been paired")
        XCTAssertEqual(SecureStoreError(.biometryDisconnected).reason,
                       "Device supports biometry only via removable accessories and the paired accessory is not connected.")
        XCTAssertEqual(SecureStoreError(.invalidDimensions).reason,
                       "Dimensions of embedded UI are invalid")
        #endif
        XCTAssertEqual(SecureStoreError(.notInteractive).reason,
                       "Displaying the required authentication user interface is forbidden")
        XCTAssertEqual(SecureStoreError(.invalidatedByHandleRequest).reason,
                       "Invalidated by handle request")
        XCTAssertEqual(SecureStoreError(.viewServiceInitializationFailure).reason,
                       "Invalidated due to view service initialization failure")
        XCTAssertEqual(SecureStoreError(.authenticationTimedOut).reason,
                       "Authentication timed out")
        XCTAssertEqual(SecureStoreError(.uiActivationTimedOut).reason,
                       "UI activation timed out after 5 seconds")
        XCTAssertEqual(SecureStoreError(.unknownLAError).reason,
                       "Unknown LAError")
        XCTAssertEqual(SecureStoreError(.unknownNSError).reason,
                       "Unknow NSError")
        XCTAssertEqual(SecureStoreError(.noResultOrError).reason,
                       "No result or error returned")
    }
}

struct SecureStoreErrorTests {
    static let allSecureStoreError = [
        (error: SecureStoreError(.unableToRetrieveFromUserDefaults), debugDescription: "Error Domain=SecureStoreErrorKind Code=1001 \"unableToRetrieveFromUserDefaults\""),
        (error: SecureStoreError(.cantDeleteKey), debugDescription: "Error Domain=SecureStoreErrorKind Code=1002 \"cantDeleteKey\""),
        (error: SecureStoreError(.cantStoreKey), debugDescription: "Error Domain=SecureStoreErrorKind Code=1003 \"cantStoreKey\""),
        (error: SecureStoreError(.cantRetrieveKey), debugDescription: "Error Domain=SecureStoreErrorKind Code=1004 \"cantRetrieveKey\""),
        (error: SecureStoreError(.cantEncryptData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1005 \"cantEncryptData\""),
        (error: SecureStoreError(.cantDecryptData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1006 \"cantDecryptData\""),
        (error: SecureStoreError(.cantEncodeData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1007 \"cantEncodeData\""),
        (error: SecureStoreError(.cantDecodeData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1008 \"cantDecodeData\""),
        (error: SecureStoreError(.cantFormatData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1009 \"cantFormatData\""),
        (error: SecureStoreError(.authenticationFailed), debugDescription: "Error Domain=SecureStoreErrorKind Code=2001 \"authenticationFailed\""),
        (error: SecureStoreError(.userCancel), debugDescription: "Error Domain=SecureStoreErrorKind Code=2002 \"userCancel\""),
        (error: SecureStoreError(.userFallback), debugDescription: "Error Domain=SecureStoreErrorKind Code=2003 \"userFallback\""),
        (error: SecureStoreError(.systemCancel), debugDescription: "Error Domain=SecureStoreErrorKind Code=2004 \"systemCancel\""),
        (error: SecureStoreError(.passcodeNotSet), debugDescription: "Error Domain=SecureStoreErrorKind Code=2005 \"passcodeNotSet\""),
        (error: SecureStoreError(.biometryNotAvailable), debugDescription: "Error Domain=SecureStoreErrorKind Code=2006 \"biometryNotAvailable\""),
        (error: SecureStoreError(.biometryNotEnrolled), debugDescription: "Error Domain=SecureStoreErrorKind Code=2007 \"biometryNotEnrolled\""),
        (error: SecureStoreError(.biometryLockout), debugDescription: "Error Domain=SecureStoreErrorKind Code=2008 \"biometryLockout\""),
        (error: SecureStoreError(.appCancel), debugDescription: "Error Domain=SecureStoreErrorKind Code=2009 \"appCancel\""),
        (error: SecureStoreError(.invalidContext), debugDescription: "Error Domain=SecureStoreErrorKind Code=2010 \"invalidContext\""),
        (error: SecureStoreError(.companionNotAvailable), debugDescription: "Error Domain=SecureStoreErrorKind Code=2011 \"companionNotAvailable\""),
        (error: SecureStoreError(.notInteractive), debugDescription: "Error Domain=SecureStoreErrorKind Code=2012 \"notInteractive\""),
        (error: SecureStoreError(.invalidatedByHandleRequest), debugDescription: "Error Domain=SecureStoreErrorKind Code=2013 \"invalidatedByHandleRequest\""),
        (error: SecureStoreError(.viewServiceInitializationFailure), debugDescription: "Error Domain=SecureStoreErrorKind Code=2014 \"viewServiceInitializationFailure\""),
        (error: SecureStoreError(.uiActivationTimedOut), debugDescription: "Error Domain=SecureStoreErrorKind Code=2015 \"uiActivationTimedOut\""),
        (error: SecureStoreError(.authenticationTimedOut), debugDescription: "Error Domain=SecureStoreErrorKind Code=2016 \"authenticationTimedOut\""),
        (error: SecureStoreError(.noResultOrError), debugDescription: "Error Domain=SecureStoreErrorKind Code=1000 \"noResultOrError\""),
        (error: SecureStoreError(.unknownLAError), debugDescription: "Error Domain=SecureStoreErrorKind Code=2000 \"unknownLAError\""),
        (error: SecureStoreError(.unknownNSError), debugDescription: "Error Domain=SecureStoreErrorKind Code=3001 \"unknownNSError\"")
    ]

    #if os(macOS)
    static let allMacOSErrors = [
        (error: SecureStoreError(.watchNotAvailable), debugDescription: "Error Domain=SecureStoreErrorKind Code=2101 \"watchNotAvailable\""),
        (error: SecureStoreError(.biometryNotPaired), debugDescription: "Error Domain=SecureStoreErrorKind Code=2102 \"biometryNotPaired\""),
        (error: SecureStoreError(.biometryDisconnected), debugDescription: "Error Domain=SecureStoreErrorKind Code=2103 \"biometryDisconnected\""),
        (error: SecureStoreError(.invalidDimensions), debugDescription: "Error Domain=SecureStoreErrorKind Code=2104 \"invalidDimensions\"")
        ]
    #endif

    @Test
    func test_domain() async throws {
        #expect(SecureStoreError.errorDomain == "SecureStoreErrorKind")
    }

    @Test("assert debugDescription", arguments: SecureStoreErrorTests.allSecureStoreError)
    func test_debugDescription(sut: SecureStoreError, debugDescription: String) async throws {
        #expect(sut.debugDescription == debugDescription)
    }

    #if os(macOS)
    @Test("assert debugDescription for non iOS errors", arguments: SecureStoreErrorTests.allMacOSErrors)
    func test_debugDescriptionForMacOSErrors(sut: SecureStoreError, debugDescription: String) async throws {
        #expect(sut.debugDescription == debugDescription)
    }
    #endif

}
