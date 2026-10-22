import Foundation

public struct SecureStorageConfiguration {

    public typealias LocalAuthenticationLocalizedStringsProvider = @Sendable () -> LocalAuthenticationLocalizedStrings?

    public static let localAuthenticationLocalizedStringsProviderNil: LocalAuthenticationLocalizedStringsProvider = {
        nil
    }

    let id: String
    let accessControlLevel: AccessControlLevel
    let localAuthStringsProvider: LocalAuthenticationLocalizedStringsProvider
    let localAuthStrings: LocalAuthenticationLocalizedStrings?
    
    public init(id: String,
                accessControlLevel: AccessControlLevel,
                localAuthStrings: LocalAuthenticationLocalizedStrings? = nil) {
        self.id = id
        self.accessControlLevel = accessControlLevel
        self.localAuthStrings = localAuthStrings
        self.localAuthStringsProvider = Self.localAuthenticationLocalizedStringsProviderNil
    }

    public init(id: String,
                accessControlLevel: AccessControlLevel,
                localAuthStringsProvider: @escaping LocalAuthenticationLocalizedStringsProvider) {
        self.id = id
        self.accessControlLevel = accessControlLevel
        self.localAuthStrings = nil
        self.localAuthStringsProvider = localAuthStringsProvider
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
