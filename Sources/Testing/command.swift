import CryptoService
import Foundation

@main
struct Test {
    static func main() throws {
        let jwtString = """
    eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3MzMyMzYyNDUsImF1ZCI6ImJhY2tlbmQtYXBpLWpsLnRva2VuLmRldi5hY2NvdW50Lmdvdi51ayIsImp0aSI6IjQ1QzY0QjFBLUVEQTktNDQwMC1CMTA5LUQ1QzQ5NTlCQUYwRSIsImlzcyI6ImJZcmN1UlZ2bnlsdkVnWVNTYkJqd1h6SHJ3SiJ9
    """
        let jwtData = Data(jwtString.utf8)
        
        let service = try CryptoSigningService(
            configuration: .init(id: "", accessControlLevel: .open)
        )
        let signature = try service.sign(data: jwtData)
        
        print(jwtString + "." + signature.base64URLEncodedString)
    }
}

extension Data {
    var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}
