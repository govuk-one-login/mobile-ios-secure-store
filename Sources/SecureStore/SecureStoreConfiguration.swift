import Foundation

// TODO: simplify back to a single ID here and manage the complexity inside the service
// cannot migrate private keys, but can (potentially) migrate encrypted things
public struct SecureStorageConfiguration {
    let id: String
    let newID: String
    let accessControlLevel: AccessControlLevel
    let localAuthStrings: LocalAuthenticationLocalizedStrings?
    
    public init(
        id: String,
        accessControlLevel: AccessControlLevel,
        localAuthStrings: LocalAuthenticationLocalizedStrings? = nil
    ) {
        self.id = id
        self.newID = id + "PrivateKey"
        self.accessControlLevel = accessControlLevel
        self.localAuthStrings = localAuthStrings
    }
    
    public enum AccessControlLevel {
        case `open`
        case anyBiometricsOnly
        case anyBiometricsOrPasscode
        case currentBiometricsOnly
        case currentBiometricsOrPasscode
        
        var flags: SecAccessControlCreateFlags {
            switch self {
            case .open:
                return []
            case .anyBiometricsOnly:
                return [.privateKeyUsage, .biometryAny]
            case .anyBiometricsOrPasscode:
                return [.privateKeyUsage, .userPresence]
            case .currentBiometricsOnly:
                return [.privateKeyUsage, .biometryCurrentSet]
            case .currentBiometricsOrPasscode:
                return [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]
            }
        }
    }
}
