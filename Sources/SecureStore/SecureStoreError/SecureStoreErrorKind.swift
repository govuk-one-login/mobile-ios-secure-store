import GDSUtilities

public enum SecureStoreErrorKind: String, GDSErrorKind, CaseIterable {
    case unableToRetrieveFromUserDefaults
    case cantDeleteKey
    case cantStoreKey
    case cantRetrieveKey
    case cantEncryptData
    case cantDecryptData
    case cantEncodeData
    case cantDecodeData
    case cantFormatData

    // LocalAuthentication errors mapped to the below
    case recoverable
    case unrecoverable
    case userCancelled
    case noLocalAuthEnrolled
}
