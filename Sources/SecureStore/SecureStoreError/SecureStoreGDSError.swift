import GDSUtilities

public typealias SecureStoreError = SecureStoreBaseError<ErrorKind.SecureStore>

public struct SecureStoreBaseError<Kind: GDSErrorKind>: GDSError {
    public let kind: Kind
    public let reason: String?
    public let endpoint: String?
    public let statusCode: Int?
    public let file: String
    public let function: String
    public let line: Int
    public let resolvable: Bool
    public let originalError: Error?
    public let additionalParameters: [String: any Sendable]

    public init(
        kind: Kind,
        reason: String?,
        endpoint: String?,
        statusCode: Int?,
        file: String,
        function: String,
        line: Int,
        resolvable: Bool,
        originalError: Error?,
        additionalParameters: [String: any Sendable]
    ) {
        self.kind = kind
        self.reason = reason
        self.endpoint = endpoint
        self.statusCode = statusCode
        self.file = file
        self.function = function
        self.line = line
        self.resolvable = resolvable
        self.originalError = originalError
        self.additionalParameters = additionalParameters
    }
}
