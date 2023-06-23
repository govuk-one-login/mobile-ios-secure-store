# SecureStore

Implementation of SecureStore.

## Installation

To use SecureStore in a SwiftPM project:

1. Add the following line to the dependencies in your `Package.swift` file:

```swift
.package(url: "https://github.com/alphagov/di-ipv-dca-mob-ios", from: "1.0.0"),
```

2. Add `SecureStore` as a dependency for your target:

```swift
.target(name: "MyTarget", dependencies: [
  .product(name: "SecureStore", package: "dcmaw-securestore"),
  "AnotherModule"
]),
```

3. Add `import SecureStore` in your source code.

## Package description

The main `SecureStore` Package contains protocols and an Keychain implementation that can be used to build SecureStore into the app. SecureStore is a wrapper around Apple's Keychain service so that you can easily save, read and delete items from the local iOS Keychain

> Within Sources/SecureStore exist the following protocols and Type for enabling items to be saved to the locak Keychain storage

`saveItem` is usable for saving items to the `SecureStore`

`readItem` is usable for reading items from the `SecureStore`

`deleteItem` is usable for deleting items from the `SecureStore`

## Example Implementation

#### Example of saving/retriving and deleting items to the SecureStore

```swift
import SecureStore

final class ViewController: UIViewController {
    private let keychainService: KeychainStorable
    
    init(keychainService: KeychainStorable) {
        self.keychainService = KeychainService(key: "ItemKey")
        super.init()
    }
    
    @IBAction private func didTapSaveButton() {
        do {
            try keychainService.saveItem("This item")
        } catch {
            print("error saving")
        }
    }
    
    @IBAction private func didTapRetrieveButton() {
        do {
            let item = try keychainService.retrieveItem()
            
            if let item {
                print(item)
            }
        } catch {
            print("error retrieving")
        }
    }
        
    @IBAction private func didTapDeleteButton() {
        do {
            try keychainService.deleteItem()
        } catch {
            print("error deleting")
        }
    }
}
```
