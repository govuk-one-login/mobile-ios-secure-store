import Foundation

public enum SecureStoreError: Error {
    case unableToRetrieveFromUserDefaults
    case cantGetPublicKeyFromPrivateKey
    case cantStoreKey
    case cantRetrieveKey
    case cantEncryptData
    case cantDecryptData
    case cantInitialiseData
}
