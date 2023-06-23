//
//  KeychainStorable.swift
//  Core
//

import Foundation

/// KeychainStorable
///
/// Used for saving items to keychain storage
public protocol KeychainStorable {
    func saveItem(item: String) throws
    func readItem() throws -> String?
    func deleteItem() throws
}
