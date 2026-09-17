import GDSUtilities

public enum SecureStoreErrorKind: Int, GDSErrorKind {
    
    // MARK: SecureStoreErrorKind
    case noResultOrError = 1000
    case unableToRetrieveFromUserDefaults = 1001
    case cantDeleteKey = 1002
    case cantStoreKey = 1003
    case cantRetrieveKey = 1004
    case cantEncryptData = 1005
    case cantDecryptData = 1006
    case cantEncodeData = 1007
    case cantDecodeData = 1008
    case cantFormatData = 1009

    // MARK: LAErrorDomain
    case unknownLAError = 2000
    case authenticationFailed = 2001 // -1
    case userCancel = 2002 // -2
    case userFallback = 2003 // -3
    case systemCancel = 2004 // -4
    case passcodeNotSet = 2005 // -5
    case biometryNotAvailable = 2006 // -6
    case biometryNotEnrolled = 2007 // -7
    case biometryLockout = 2008 // -8
    case appCancel = 2009 // -9
    case invalidContext = 2010 // -10
    case companionNotAvailable = 2011 // -11
    case notInteractive = 2012 // -1004
    case invalidatedByHandleRequest = 2013 // 4
    case viewServiceInitializationFailure = 2014 // 6
    case uiActivationTimedOut = 2015 // -1000
    case authenticationTimedOut = 2016 // -1003
    @available(iOS, unavailable) case watchNotAvailable = 2101 // -11
    @available(iOS, unavailable) case biometryNotPaired = 2102 // -12
    @available(iOS, unavailable) case biometryDisconnected = 2103 // -13
    @available(iOS, unavailable) case invalidDimensions = 2104 // -14

    // MARK: NSErrorDomain
    case unknownNSError = 3001
    
    public var description: String {
        switch self {
        case .unableToRetrieveFromUserDefaults:
            return "Error while retrieving item from User Defaults"
        case .cantDeleteKey:
            return "Error while deleting key from the keychain"
        case .cantStoreKey:
            return "Error while storing key to the keychain"
        case .cantRetrieveKey:
            return "Error while retrieving key from the keychain"
        case .cantEncryptData:
            return "Error while encrypting data"
        case .cantDecryptData:
            return "Error while decrypting data"
        case .cantEncodeData:
            return "Error while encoding data"
        case .cantDecodeData:
            return "Error while decoding data"
        case .cantFormatData:
            return "Error while formatting data"
        case .authenticationFailed:
            return "User failed to provide valid credentials"
        case .userCancel:
            return "User cancelled the biometric prompt"
        case .userFallback:
            return "No fallback is available for the authentication policy"
        case .systemCancel:
            return "System cancelled authentication"
        case .passcodeNotSet:
            return "A passcode isn't set on the device"
        case .biometryNotAvailable:
            return "No biometry available on the device"
        case .biometryNotEnrolled:
            return "Biometry is not enrolled on the device"
        case .biometryLockout:
            return "Biometry is locked out"
        case .appCancel:
            return "App cancelled authentication"
        case .invalidContext:
            return "The context was previously invalidated"
        case .companionNotAvailable:
            return "No paired companion device nearby"
        case .watchNotAvailable:
            return "No paired watch nearby"
        case .biometryNotPaired:
            return "Device supports biometry only via removable accessories and no accessory has been paired"
        case .biometryDisconnected:
            return "Device supports biometry only via removable accessories and the paired accessory is not connected."
        case .invalidDimensions:
            return "Dimensions of embedded UI are invalid"
        case .notInteractive:
            return "Displaying the required authentication user interface is forbidden"
        case .invalidatedByHandleRequest:
            return "Invalidated by handle request"
        case .viewServiceInitializationFailure:
            return "Invalidated due to view service initialization failure"
        case .authenticationTimedOut:
            return "Authentication timed out"
        case .uiActivationTimedOut:
            return "UI activation timed out after 5 seconds"
        case .unknownLAError:
            return "Unknown LAError"
        case .unknownNSError:
            return "Unknow NSError"
        case .noResultOrError:
            return "No result or error returned"
        }
    }
}
