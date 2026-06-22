import GDSUtilities

public enum SecureStoreErrorKind: Int, GDSErrorKind {
    case unableToRetrieveFromUserDefaults = 1001
    case cantDeleteKey = 1002
    case cantStoreKey = 1003
    case cantRetrieveKey = 1004
    case cantEncryptData = 1005
    case cantDecryptData = 1006
    case cantEncodeData = 1007
    case cantDecodeData = 1008
    case cantFormatData = 1009

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
    @available(iOS, unavailable) case watchNotAvailable = 2101 // -11
    @available(iOS, unavailable) case biometryNotPaired = 2102 // -12
    @available(iOS, unavailable) case biometryDisconnected = 2103 // -13
    @available(iOS, unavailable) case invalidDimensions = 2104 // -14
    case notInteractive = 2105 // -1004
    
    case invalidatedByHandleRequest = 3001 // 4
    case viewServiceInitializationFailure = 3002 // 6
    case uiActivationTimedOut = 3003 // -1000
    case authenticationTimedOut = 3004 // -1003

    case noResultOrError = 4001
    case unknownLAError = 4002
    case unknownNSError = 4003
    
    public var description: String {
        switch self {
        case .unableToRetrieveFromUserDefaults:
            return "unableToRetrieveFromUserDefaults"
        case .cantDeleteKey:
            return "cantDeleteKey"
        case .cantStoreKey:
            return "cantStoreKey"
        case .cantRetrieveKey:
            return "cantRetrieveKey"
        case .cantEncryptData:
            return "cantEncryptData"
        case .cantDecryptData:
            return "cantDecryptData"
        case .cantEncodeData:
            return "cantEncodeData"
        case .cantDecodeData:
            return "cantDecodeData"
        case .cantFormatData:
            return "cantFormatData"
        case .authenticationFailed:
            return "authenticationFailed"
        case .userCancel:
            return "userCancel"
        case .userFallback:
            return "userFallback"
        case .systemCancel:
            return "systemCancel"
        case .passcodeNotSet:
            return "passcodeNotSet"
        case .biometryNotAvailable:
            return "biometryNotAvailable"
        case .biometryNotEnrolled:
            return "biometryNotEnrolled"
        case .biometryLockout:
            return "biometryLockout"
        case .appCancel:
            return "appCancel"
        case .invalidContext:
            return "invalidContext"
        case .companionNotAvailable:
            return "companionNotAvailable"
        case .watchNotAvailable:
            return "watchNotAvailable"
        case .biometryNotPaired:
            return "biometryNotPaired"
        case .biometryDisconnected:
            return "biometryDisconnected"
        case .invalidDimensions:
            return "invalidDimensions"
        case .notInteractive:
            return "notInteractive"
        case .invalidatedByHandleRequest:
            return "invalidatedByHandleRequest"
        case .viewServiceInitializationFailure:
            return "viewServiceInitializationFailure"
        case .uiActivationTimedOut:
            return "uiActivationTimedOut"
        case .authenticationTimedOut:
            return "authenticationTimedOut"
        case .noResultOrError:
            return "noResultOrError"
        case .unknownLAError:
            return "unknownLAError"
        case .unknownNSError:
            return "unknownNSError"
        }
    }
}
