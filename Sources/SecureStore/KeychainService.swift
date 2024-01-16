import Foundation
import JWTDecode

// Boilerplate "GenericKeychain" code written by Apple
// https://developer.apple.com/library/archive/samplecode/GenericKeychain/Introduction/Intro.html

/// KeychainError
///
/// Conforms to `Error` and adds additional `status` property if needed.
public enum KeychainError: Error {
    case noToken
    case expiredToken
    case failedToDecodeJWT
    case cantEncodeToken
    case unexpectedTokenData
    case unexpectedItemData
    case unhandledError(status: OSStatus)
}

public struct KeychainService {
    let service: String
    private(set) var account: String

    // MARK: Initialisation
    /// - Parameters:
    /// - id: They key of the key/value pair, used to store the item (the value).
    public init(id: String) {
        self.service = KeychainConfiguration.serviceName
        self.account = id
    }
}

// MARK: Keychain access - Read, Save, Delete
/// Extension on KeychainService
/// Handles all the logic of reading, saving and deleting items.
extension KeychainService: KeychainStorable {
    public func readItem() throws -> String? {
        /*
         Build a query to find the item that matches the service, account and
         access group.
         */
        var query: [String: AnyObject] = KeychainService.keychainQuery(withService: service,
                                                                       account: account)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue

        // Try to fetch the existing keychain item that matches the query.
        var queryResult: AnyObject?
        let status: OSStatus = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }

        // Check the return status and throw an error if appropriate.
        guard status != errSecItemNotFound else { throw KeychainError.noToken }
        guard status == noErr else { throw KeychainError.unhandledError(status: status) }

        // Parse the token string from the query result.
        guard let existingItem = queryResult as? [String: AnyObject],
              let tokenData = existingItem[kSecValueData as String] as? Data,
              let token = String(data: tokenData, encoding: .utf8) else {
            throw KeychainError.unexpectedTokenData
        }

        return token
    }

    public func saveItem(item: String) throws {
        // Encode the token into an Data object.
        guard let encodedToken = item.data(using: .utf8) else {
            throw KeychainError.cantEncodeToken
        }

        do {
            // Check for an existing item in the keychain.
            try _ = readItem()

            // Update the existing item with the new token.
            var attributesToUpdate = [String: AnyObject]()
            attributesToUpdate[kSecValueData as String] = encodedToken as AnyObject?

            let query = KeychainService.keychainQuery(withService: service,
                                                      account: account)
            let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)

            // Throw an error if an unexpected status was returned.
            guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        } catch KeychainError.noToken {
            /*
             No token was found in the keychain. Create a dictionary to save
             as a new keychain item.
             */
            var newItem = KeychainService.keychainQuery(withService: service,
                                                        account: account)
            newItem[kSecValueData as String] = encodedToken as AnyObject?

            // Add a the new item to the keychain.
            let status = SecItemAdd(newItem as CFDictionary, nil)

            // Throw an error if an unexpected status was returned.
            guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        }
    }

    public func deleteItem() throws {
        // Delete the existing item from the keychain.
        let query = KeychainService.keychainQuery(withService: service,
                                                  account: account)
        let status = SecItemDelete(query as CFDictionary)

        // Throw an error if an unexpected status was returned.
        guard status == noErr || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
}

// MARK: Keychain Query
/// Extension on KeychainService
///
/// Handles building the keychain query for searching
extension KeychainService {
    private static func keychainQuery(withService service: String, account: String? = nil) -> [String: AnyObject] {
        var query = [String: AnyObject]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrService as String] = service as AnyObject?

        if let account = account {
            query[kSecAttrAccount as String] = account as AnyObject?
        }

        return query
    }
}
