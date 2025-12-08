// does not conform to `CustomStringConvertable` or `CustomDebugStringConvertable` to avoid infinite loop
public protocol AnyErrorKind:
    RawRepresentable,
    Equatable where RawValue == String {
    var logToCrashlytics: Bool { get }
}

extension AnyErrorKind {
    public var logToCrashlytics: Bool {
        true
    }
}

extension AnyErrorKind {
    public var description: String {
        rawValue == "\(self)" ?
            "\(self)" :
            "\(self) - \(rawValue)"
    }
}

public enum ErrorKind {}
