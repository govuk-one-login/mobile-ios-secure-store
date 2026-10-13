import GDSUtilities
import LocalAuthentication
@testable import SecureStore
import Testing

struct SecureStoreErrorTests {

    struct Case: Sendable {
        let error: SecureStoreError
        let debugDescription: String
        let kind: String
    }

    static let allSecureStoreError = [
        // swiftlint:disable line_length
        Case(error: SecureStoreError(.unableToRetrieveFromUserDefaults), debugDescription: "Error Domain=SecureStoreErrorKind Code=1001 \"Error while retrieving item from User Defaults\"", kind: "unableToRetrieveFromUserDefaults"),
        Case(error: SecureStoreError(.cantDeleteKey), debugDescription: "Error Domain=SecureStoreErrorKind Code=1002 \"Error while deleting key from the keychain\"", kind: "cantDeleteKey"),
        Case(error: SecureStoreError(.cantStoreKey), debugDescription: "Error Domain=SecureStoreErrorKind Code=1003 \"Error while storing key to the keychain\"", kind: "cantStoreKey"),
        Case(error: SecureStoreError(.cantRetrieveKey), debugDescription: "Error Domain=SecureStoreErrorKind Code=1004 \"Error while retrieving key from the keychain\"", kind: "cantRetrieveKey"),
        Case(error: SecureStoreError(.cantEncryptData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1005 \"Error while encrypting data\"", kind: "cantEncryptData"),
        Case(error: SecureStoreError(.cantDecryptData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1006 \"Error while decrypting data\"", kind: "cantDecryptData"),
        Case(error: SecureStoreError(.cantEncodeData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1007 \"Error while encoding data\"", kind: "cantEncodeData"),
        Case(error: SecureStoreError(.cantDecodeData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1008 \"Error while decoding data\"", kind: "cantDecodeData"),
        Case(error: SecureStoreError(.cantFormatData), debugDescription: "Error Domain=SecureStoreErrorKind Code=1009 \"Error while formatting data\"", kind: "cantFormatData"),
        Case(error: SecureStoreError(.authenticationFailed), debugDescription: "Error Domain=SecureStoreErrorKind Code=2001 \"User failed to provide valid credentials\"", kind: "authenticationFailed"),
        Case(error: SecureStoreError(.userCancel), debugDescription: "Error Domain=SecureStoreErrorKind Code=2002 \"User cancelled the biometric prompt\"", kind: "userCancel"),
        Case(error: SecureStoreError(.userFallback), debugDescription: "Error Domain=SecureStoreErrorKind Code=2003 \"No fallback is available for the authentication policy\"", kind: "userFallback"),
        Case(error: SecureStoreError(.systemCancel), debugDescription: "Error Domain=SecureStoreErrorKind Code=2004 \"System cancelled authentication\"", kind: "systemCancel"),
        Case(error: SecureStoreError(.passcodeNotSet), debugDescription: "Error Domain=SecureStoreErrorKind Code=2005 \"A passcode isn't set on the device\"", kind: "passcodeNotSet"),
        Case(error: SecureStoreError(.biometryNotAvailable), debugDescription: "Error Domain=SecureStoreErrorKind Code=2006 \"No biometry available on the device\"", kind: "biometryNotAvailable"),
        Case(error: SecureStoreError(.biometryNotEnrolled), debugDescription: "Error Domain=SecureStoreErrorKind Code=2007 \"Biometry is not enrolled on the device\"", kind: "biometryNotEnrolled"),
        Case(error: SecureStoreError(.biometryLockout), debugDescription: "Error Domain=SecureStoreErrorKind Code=2008 \"Biometry is locked out\"", kind: "biometryLockout"),
        Case(error: SecureStoreError(.appCancel), debugDescription: "Error Domain=SecureStoreErrorKind Code=2009 \"App cancelled authentication\"", kind: "appCancel"),
        Case(error: SecureStoreError(.invalidContext), debugDescription: "Error Domain=SecureStoreErrorKind Code=2010 \"The context was previously invalidated\"", kind: "invalidContext"),
        Case(error: SecureStoreError(.companionNotAvailable), debugDescription: "Error Domain=SecureStoreErrorKind Code=2011 \"No paired companion device nearby\"", kind: "companionNotAvailable"),
        Case(error: SecureStoreError(.notInteractive), debugDescription: "Error Domain=SecureStoreErrorKind Code=2012 \"Displaying the required authentication user interface is forbidden\"", kind: "notInteractive"),
        Case(error: SecureStoreError(.invalidatedByHandleRequest), debugDescription: "Error Domain=SecureStoreErrorKind Code=2013 \"Invalidated by handle request\"", kind: "invalidatedByHandleRequest"),
        Case(error: SecureStoreError(.viewServiceInitializationFailure), debugDescription: "Error Domain=SecureStoreErrorKind Code=2014 \"Invalidated due to view service initialization failure\"", kind: "viewServiceInitializationFailure"),
        Case(error: SecureStoreError(.uiActivationTimedOut), debugDescription: "Error Domain=SecureStoreErrorKind Code=2015 \"UI activation timed out after 5 seconds\"", kind: "uiActivationTimedOut"),
        Case(error: SecureStoreError(.authenticationTimedOut), debugDescription: "Error Domain=SecureStoreErrorKind Code=2016 \"Authentication timed out\"", kind: "authenticationTimedOut"),
        Case(error: SecureStoreError(.noResultOrError), debugDescription: "Error Domain=SecureStoreErrorKind Code=1000 \"No result or error returned\"", kind: "noResultOrError"),
        Case(error: SecureStoreError(.unknownLAError), debugDescription: "Error Domain=SecureStoreErrorKind Code=2000 \"Unknown LAError\"", kind: "unknownLAError"),
        Case(error: SecureStoreError(.unknownNSError), debugDescription: "Error Domain=SecureStoreErrorKind Code=3001 \"Unknown NSError\"", kind: "unknownNSError")
        // swiftlint:enable line_length
    ]

#if os(macOS)
    static let allMacOSErrors = [
        // swiftlint:disable line_length
        Case(error: SecureStoreError(.watchNotAvailable), debugDescription: "Error Domain=SecureStoreErrorKind Code=2101 \"No paired watch nearby\"", kind: "watchNotAvailable"),
        Case(error: SecureStoreError(.biometryNotPaired), debugDescription: "Error Domain=SecureStoreErrorKind Code=2102 \"Device supports biometry only via removable accessories and no accessory has been paired\"", kind: "biometryNotPaired"),
        Case(error: SecureStoreError(.biometryDisconnected), debugDescription: "Error Domain=SecureStoreErrorKind Code=2103 \"Device supports biometry only via removable accessories and the paired accessory is not connected.\"", kind: "biometryDisconnected"),
        Case(error: SecureStoreError(.invalidDimensions), debugDescription: "Error Domain=SecureStoreErrorKind Code=2104 \"Dimensions of embedded UI are invalid\"", kind: "invalidDimensions")
    ]
    // swiftlint:enable line_length
#endif
    
    @Test
    func test_domain() async throws {
        #expect(SecureStoreError.errorDomain == "SecureStoreErrorKind")
    }

    @Test("assert debugDescription", arguments: SecureStoreErrorTests.allSecureStoreError)
    func test_debugDescription(testCase: Case) async throws {
        #expect(testCase.error.debugDescription == testCase.debugDescription)
    }

    /// // swiftlint:disable line_length
    /// The `kind` found in the `userInfo` **must** hold a unique String identifier that describes the error as reported on analytics
    /// - Seealso: https://govukverify.atlassian.net/wiki/spaces/DCMAW/pages/3787195450/GOV.UK+One+Login+app+-+Error+handling#Secure-store-errors
    /// // swiftlint:enable line_length
    @Test("assert kind", arguments: SecureStoreErrorTests.allSecureStoreError)
    func test_kind(testCase: Case) async throws {
        #expect(testCase.error.errorUserInfo["kind"] as? String == testCase.kind)
    }

#if os(macOS)
    @Test("assert debugDescription for non iOS errors", arguments: SecureStoreErrorTests.allMacOSErrors)
    func test_debugDescriptionForMacOSErrors(testCase: Case) async throws {
        #expect(testCase.error.debugDescription == testCase.debugDescription)
    }
#endif

    @Test("Error returned by biometric error handling is mapped to expected SecureStoreError",
          arguments:
            [(SecureStoreError.biometricErrorHandling(error: nil), SecureStoreError(.noResultOrError)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.authenticationFailed) as NSError), SecureStoreError(.authenticationFailed)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.userCancel) as NSError), SecureStoreError(.userCancel)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.userFallback) as NSError), SecureStoreError(.userFallback)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.systemCancel) as NSError), SecureStoreError(.systemCancel)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.passcodeNotSet) as NSError), SecureStoreError(.passcodeNotSet)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.biometryNotAvailable) as NSError), SecureStoreError(.biometryNotAvailable)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.biometryNotEnrolled) as NSError), SecureStoreError(.biometryNotEnrolled)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.biometryLockout) as NSError), SecureStoreError(.biometryLockout)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.appCancel) as NSError), SecureStoreError(.appCancel)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.invalidContext) as NSError), SecureStoreError(.invalidContext)),
             (SecureStoreError.biometricErrorHandling(error: LAError(.notInteractive) as NSError), SecureStoreError(.notInteractive)),
             (SecureStoreError.biometricErrorHandling(error: LAError(LAError.Code(rawValue: 4)!) as NSError), SecureStoreError(.invalidatedByHandleRequest)),
             (SecureStoreError.biometricErrorHandling(error: LAError(LAError.Code(rawValue: 6)!) as NSError), SecureStoreError(.viewServiceInitializationFailure)),
             (SecureStoreError.biometricErrorHandling(error: LAError(LAError.Code(rawValue: -1000)!) as NSError), SecureStoreError(.uiActivationTimedOut)),
             (SecureStoreError.biometricErrorHandling(error: LAError(LAError.Code(rawValue: -1003)!) as NSError), SecureStoreError(.authenticationTimedOut)),
             (SecureStoreError.biometricErrorHandling(error: LAError(LAError.Code(rawValue: -999)!) as NSError), SecureStoreError(.unknownLAError))])
    func assertBionetricError(actual: SecureStoreError, expected: SecureStoreError) {
        #expect(actual == expected)
    }

#if os(macOS)
    @Test("Error returned by biometric error handling is mapped to expected SecureStoreError for non iOS errors",
          arguments:
            [(SecureStoreError.biometricErrorHandling(error: (LAError(.watchNotAvailable) as NSError)), SecureStoreError(.watchNotAvailable)),
             (SecureStoreError.biometricErrorHandling(error: (LAError(.biometryNotPaired) as NSError)), SecureStoreError(.biometryNotPaired)),
             (SecureStoreError.biometricErrorHandling(error: (LAError(.biometryDisconnected) as NSError)), SecureStoreError(.biometryDisconnected)),
             (SecureStoreError.biometricErrorHandling(error: (LAError(.invalidDimensions) as NSError)), SecureStoreError(.invalidDimensions))])
    func assertBionetricError(actual: SecureStoreError, expected: SecureStoreError) {
        #expect(actual == expected)
    }
#endif

    static let errSecParam = NSError(domain: NSOSStatusErrorDomain,code: -50)
    static let unknown = NSError(domain: NSOSStatusErrorDomain,code: -100)

    @Test(arguments:
            [(SecureStoreError.biometricErrorHandling(error: errSecParam), SecureStoreErrorKind.cantDecryptData, originalError: errSecParam),
             (SecureStoreError.biometricErrorHandling(error: unknown), SecureStoreErrorKind.unknownNSError, originalError: unknown)])
    func assertBionetricErrorKind(actual: SecureStoreError, kind: SecureStoreErrorKind, originalError: NSError) {
        #expect(actual.kind == kind)
        #expect(actual.originalError as? NSError ==  originalError)
    }

    @Test
    func secureStoreError_errorReasonReturnsNil() {
        enum TestErrorKind: Int, GDSErrorKind {
            case errorKindWithNoReason = 1

            var description: String {
                "errorKindWithNoReason"
            }
        }

        #expect(GDSSecureStoreError(TestErrorKind.errorKindWithNoReason).reason == nil)
    }
}
