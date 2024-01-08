import Foundation

public struct SecureStorageConfiguration {
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
                [.privateKeyUsage, .biometryAny, .touchIDAny]
            case .currentBiometricsOnly:
                [.privateKeyUsage, .biometryCurrentSet]
            }
        }
    }
}
