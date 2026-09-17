import Foundation

struct OSStatusError: CustomNSError, LocalizedError, CustomDebugStringConvertible {
    static func make(status: OSStatus, underlyingError: Error? = nil) -> Self {
    
        var errorUserInfo: [String: any Sendable] = [:]
        
        if let errorMessage = SecCopyErrorMessageString(status, nil) {
            errorUserInfo[NSLocalizedDescriptionKey] = errorMessage as String
        }
        
        if let underlyingError {
            errorUserInfo[NSUnderlyingErrorKey] = underlyingError
        }
        
        return OSStatusError(status: status, _errorUserInfo: errorUserInfo)
    }
    
    let status: OSStatus
    private let _errorUserInfo: [String: any Sendable]
    
    // MARK: CustomNSError
    static var errorDomain: String {
        NSOSStatusErrorDomain
    }
    
    var errorCode: Int {
        return Int(status)
    }
    
    var errorUserInfo: [String: Any] {
        _errorUserInfo
    }
    
    // MARK: CustomDebugStringConvertible
    
    var debugDescription: String {
        let userInfo = _errorUserInfo.keys.sorted().map { key in
            "\(String(reflecting: key)): \(String(reflecting: _errorUserInfo[key]!))"
        }.joined(separator: ", ")
        
        return "Error Domain=\(Self.errorDomain) Code=\(errorCode) \"The operation couldn’t be completed.\" UserInfo=[\(userInfo)]"
    }

    // MARK: LocalizedError
    
    var errorDescription: String {
        return errorUserInfo[NSLocalizedDescriptionKey] as? String ?? ""
    }
}
