import GDSUtilities

public enum SecureStoreErrorKind: String, GDSErrorKind {
    case unableToRetrieveFromUserDefaults
    case cantDeleteKey
    case cantStoreKey
    case cantRetrieveKey
    case cantEncryptData
    case cantDecryptData
    case cantEncodeData
    case cantDecodeData
    case cantFormatData

    case authenticationFailed // -1
    case userCancel // -2
    case userFallback // -3
    case systemCancel // -4
    case passcodeNotSet // -5
    case biometryNotAvailable // -6
    case biometryNotEnrolled // -7
    case biometryLockout // -8
    case appCancel // -9
    case invalidContext // -10
    case companionNotAvailable // -11
    @available(iOS, unavailable) case watchNotAvailable // -11
    @available(iOS, unavailable) case biometryNotPaired // -12
    @available(iOS, unavailable) case biometryDisconnected // -13
    @available(iOS, unavailable) case invalidDimensions // -14
    case notInteractive // -1004
    
    case invalidatedByHandleRequest // 4
    case viewServiceInitializationFailure // 6
    case uiActivationTimedOut // -1000
    case authenticationTimedOut // -1003
    
    case noResultOrError
    case unknownLAError
    case unknownNSError
}
