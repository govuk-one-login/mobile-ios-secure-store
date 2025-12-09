// does not conform to `CustomStringConvertable` or `CustomDebugStringConvertable` to avoid infinite loop
public protocol AnyErrorKind: Sendable,
                              RawRepresentable,
                              Equatable where RawValue == String {
    var logToCrashlytics: Bool { get }
}

extension AnyErrorKind {
    public var logToCrashlytics: Bool {
        true
    }
}

extension AnyErrorKind where Self.RawValue == String {
    public var localizedDescription: String {
        self.rawValue
    }
}

public enum ErrorKind {}
