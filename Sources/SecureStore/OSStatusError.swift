import Foundation

struct OSStatusError: CustomNSError, CustomDebugStringConvertible {
    static func make(status: OSStatus, underlyingError: Error? = nil) -> Self {
    
        var errorUserInfo: [String: any Sendable] = [:]
        
        if let errorMessage = SecCopyErrorMessageString(status, nil) {
            errorUserInfo[NSDebugDescriptionErrorKey] = errorMessage as String
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
    
    var errorUserInfo: [String : Any] {
        _errorUserInfo
    }
    
    // MARK: CustomDebugStringConvertible
    
    var debugDescription: String {
        return errorUserInfo[NSDebugDescriptionErrorKey] as? String ?? ""
    }
}
