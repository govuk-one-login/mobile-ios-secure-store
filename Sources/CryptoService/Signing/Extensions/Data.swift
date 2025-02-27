import BigInt
import Foundation

extension Data {
    /// Base 58 is a modified variant of base 64 which avoids:
    ///   - non-alphanumeric characters (+ and /)
    ///   - letters that might look ambiguous when printed:
    ///     (0 – zero, I – capital i, O – capital o and l – lower-case L).
    func base58EncodedString() -> String {
        var bigInt = BigUInt(self)
        let base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var result = ""

        while bigInt > 0 {
            let (quotient, remainder) = bigInt.quotientAndRemainder(dividingBy: 58)
            result = String(base58[String.Index(utf16Offset: Int(remainder), in: base58)]) + result
            bigInt = quotient
        }

        for byte in self {
            if byte != 0x00 {
                break
            }
            result = "1" + result
        }
        return result
    }
    
    /// Base 64 encoding the string.
    ///
    /// Removing unallowed URL encoded character:
    ///   - "="
    ///
    /// Replacing unallowed URL encoded characters:
    ///   - "+" with "-"
    ///   - "/" with "_"
    var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}
