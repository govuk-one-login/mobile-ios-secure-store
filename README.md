# SecureStore

Implementation of SecureStore.

## Installation

To use SecureStore in a SwiftPM project:

1. Add the following line to the dependencies in your `Package.swift` file:

```swift
.package(url: "https://github.com/govuk-one-login/mobile-ios-secure-store", from: "1.0.0"),
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

The main `SecureStore` Package contains protocols and an Keychain implementation that can be used to build SecureStore into the app. SecureStore is a wrapper around Apple's Keychain service so that you can easily save, read, delete and check if items already exist in the local iOS Keychain

> Within Sources/SecureStore exist the following protocols and Type for enabling items to be saved to the locak Keychain storage

`saveItem` is usable for saving items to the `SecureStore`

`readItem` is usable for reading items from the `SecureStore`

`deleteItem` is usable for deleting items from the `SecureStore`

`deleteStore` is usable for deleting the keys generated to use `SecureEnclave`


## Example Implementation

#### Example of saving/retriving and deleting items to the SecureStore

```swift
import SecureStore

final class ViewController: UIViewController {
    private let secureStoreService: SecureStoreService
    let myData = "my_data"

    init(secureStoreService: SecureStoreService) {
        self.secureStoreService = secureStoreService
        super.init()
    }
    
    @IBAction private func didTapSaveButton() {        
        if try secureStore.checkItemExists(withKey: myData) {
            print("item already exists!")
            return
        }
        
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
        do {
            try secureStore.deleteItem(keyToDelete: myData)
        } catch {
            print("error deleting item")
        }
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
