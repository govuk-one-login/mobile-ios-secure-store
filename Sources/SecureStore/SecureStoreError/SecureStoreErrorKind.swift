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
}
