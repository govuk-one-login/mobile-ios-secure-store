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
        case anyBiometricsOnly
        case currentBiometricsOnly
        case currentBiometricsOrPasscode

        var flags: SecAccessControlCreateFlags {
            switch self {
            case .open:
                return []
            case .anyBiometricsOnly:
                return [.privateKeyUsage, .biometryAny]
            case .currentBiometricsOnly:
                return [.privateKeyUsage, .biometryCurrentSet]
            case .currentBiometricsOrPasscode:
                return [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]
            }
        }
    }
}
