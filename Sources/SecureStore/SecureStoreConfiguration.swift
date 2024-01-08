import Foundation

public struct SecureStorageConfiguration {
    // What do we use this ID for? Should it be this rather than the key being passed in?
    let id: String
    let accessControlLevel: AccessControlLevel
    
    public init(id: String, accessControlLevel: AccessControlLevel) {
        self.id = id
        self.accessControlLevel = accessControlLevel
    }
    
    public enum AccessControlLevel {
        case `open`
        case anyBiometricsOrPasscode
        case currentBiometricsOnly
        
        var flags: SecAccessControlCreateFlags {
            switch self {
            case .open:
                []
            case .anyBiometricsOrPasscode:
                //private key usage here too?
                [.privateKeyUsage, .biometryAny, .touchIDAny]
            case .currentBiometricsOnly:
                [.privateKeyUsage, .biometryCurrentSet]
            }
        }
    }
}
