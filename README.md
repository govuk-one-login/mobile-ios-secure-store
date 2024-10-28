# SecureStore

Implementations of an encrypted data store and a cryptography service.

## Installation

To use SecureStore in a SwiftPM project:

1. Add the following line to the dependencies in your `Package.swift` file:

```swift
.package(url: "https://github.com/govuk-one-login/mobile-ios-secure-store", from: "1.0.0"),
```

2. Add `SecureStore` or `CryptoService` as a dependency for your target:

```swift
.target(name: "MyTarget", dependencies: [
  .product(name: "SecureStore", package: "dcmaw-securestore"),
  .product(name: "CryptoService", package: "dcmaw-securestore"),
  "AnotherModule"
]),
```

3. Add `import SecureStore` or `import CryptoService` in your source code.

## Package description
SecureStore contains protocols and exposes a service to encrypt and store data, and decrypt and return data.
CryptoService contains protocols and exposes services to manage a cryptographic key pair, encrypt and decrypt data, and sign and expose a public key in did or jwk format.

The SecureStore package contains two modules, `SecureStore` and `CryptoService`.

**SecureStore functions to:**
- Take labelled data, encrypt it and store it locally.
- Take a label, decrypt the associated data and return it.

**CryptoService functions to:**
- Encrypt and decrypt data.
- Sign and expose the paired public key in either DID or JWK format.
- Generate, expose and delete private and public keys.

SecureStore has a dependency on CryptoService as a wrapper around Apple's Keychain service.
The key pair generated by CryptoService is an elliptic curve key pair which is stored in the Secure Enclave. You can read more about the Apple's Secure Enclave technology in their [developer documentation](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).

## SecureStore Example Implementation

> Within Sources/SecureStore exists the following public protocol and a conforming Type for enabling items to be saved to local storage.

```swift
public protocol SecureStorable {
    func saveItem(item: String, itemName: String) throws
    func readItem(itemName: String) throws -> String
    func deleteItem(itemName: String)
    func delete() throws
    func checkItemExists(itemName: String) -> Bool
}

public class SecureStoreService: SecureStorable {
    ...
}
```

#### Example of checking the existence of, saving, retrieving and deleting items or deleting the store using SecureStore.

```swift
import SecureStore

final class ViewController: UIViewController {
    private let secureStoreService: SecureStoreService
    let myData = "my_data"

    init(secureStoreService: SecureStoreService) {
        self.secureStoreService = secureStoreService
        super.init()
    }
    
    @IBAction private func didTapCheckIfItemExistsButton() {
        if secureStore.checkItemExists(withKey: myData) {
            print("item already exists!")
            return
        } else {
            print("item does not exist!")
        }
    }
    
    @IBAction private func didTapSaveButton() {
        do {
            try secureStoreService.saveItem(item: "Example data", itemName: myData)
        } catch {
            print("error saving")
        }
    }
    
    @IBAction private func didTapRetrieveButton() {
        do {
            let item = try secureStore.readItem(withName: myData)
            print(item)
        } catch {
            print("error retrieving")
        }
    }
        
    @IBAction private func didTapDeleteItemButton() {
        secureStore.deleteItem(keyToDelete: myData)
    }
    
    @IBAction private func didTapDeleteStoreButton() {
        do {
            try secureStore.deleteStore()
        } catch {
            print("error deleting store")
        }
    }
}
```

## CryptoService Example Implementation

> Within Sources/CryptoService exist the following public protocols and conforming Types to enable the functions described.

```swift
public protocol KeyStore {
    var publicKey: SecKey { get }
    var privateKey: SecKey { get }
    
    func deleteKeys() throws
}

public class CryptoKeyStore: KeyStore {
    ...
}
```

```swift
public protocol EncryptionService {
    func encryptData(dataToEncrypt: String) throws -> String
    func decryptData(dataToDecrypt: String) throws -> String
}

public class CryptoEncryptionService: EncryptionService {
    ...
}
```

```swift
public protocol SigningService {
    func publicKey(didKey: Bool) throws -> Data
    func sign(data: Data) throws -> Data
}

public class CryptoSigningService: SigningService {
    ...
}
```

#### Example of generating, accessing, and deleting keys using CryptoKeyStore

```swift
import SecureStore

final class KeyManagerService {
    private let cryptographicKeyManager: CryptoKeyStore
    
    var keys: (privateKey: SecKey, publicKey: SecKey) {
        (cryptographicKeyManager.privateKey, cryptographicKeyManager.publicKey)
    }
    
    init(configuration: CryptoServiceConfiguration) throws {
        self.cryptographicKeyManager = try CryptoKeyStore(configuration: configuration)
    }
    
    func deleteKeys() {
        do {
            try cryptographicKeyManager.deleteKeys()
        } catch {
            // handle key deletion failure
        }
    }
}
```

#### Example of encrypting and decrypting data using CryptoEncryptionService

```swift
import SecureStore

final class DataEncryptionService {
    private let encryptDataService: CryptoEncryptionService
    
    init(configuration: CryptoServiceConfiguration) throws {
        self.encryptDataService = try CryptoEncryptionService(configuration: configuration)
    }
    
    func encryptData(_ data: Data) -> String {
        do {
            return try encryptDataService.encryptData(dataToEncrypt: data)
        } catch {
            // handle encryption failure
        }
    }
    
    func decryptData(_ data: Data) -> String {
        do {
            return try encryptDataService.decryptData(dataToDecrypt: data)
        } catch {
            // handle decryption failure
        }
    }
}
```

#### Example of accessing the public key, and signing data using CryptoSigningService

```swift
import SecureStore

final class SignDataService {
    private let signingService: CryptoSigningService

    init(configuration: CryptoServiceConfiguration) throws {
        self.signingService = try CryptoSigningService(configuration: configuration)
    }
    
    func getPublicKey() -> Data {
        signingService.publicKey(didKey: true)
    }
    
    func sign(data: Data) -> {
        do {
            try signingService.sign(data: data)
        } catch {
            // handle signing error, perhaps by regenerating the keys
        }
    }
}
```
