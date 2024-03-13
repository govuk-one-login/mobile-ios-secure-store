import SwiftUI
import SecureStore
struct ContentView: View {
    @State private var encryptedData: String? = ""
    @State private var myData: String = ""
    @State private var decryptedData: String? = ""

    let secureStore: SecureStoreService

    init() {
        let localAuthStrings = [
            "localizedReason": "Local Authentication Reason",
            "localizedFallbackTitle": "Enter passcode",
            "localizedCancelTitle": "Cancel"
        ]
        let secureStore = SecureStoreService(configuration: .init(id: "Wallet-Test-01",
                                                                  accessControlLevel: .currentBiometricsOnly,
                                                                  localAuthStrings: localAuthStrings))
        self.secureStore = secureStore
    }

    var body: some View {
        ScrollView {
            VStack {
                TextField("Input your data", text: $myData)
                    .textFieldStyle(.roundedBorder)
                    .multilineTextAlignment(.center)
                    .fixedSize()

                Button("Encrypt JWT") {
                    do {
                        encryptedData = "No encrypted data"

                        if try secureStore.checkItemExists(itemName: myData) {
                            print("item already exists!")
                            encryptedData = "Item already exists!"
                            return
                        }

                        let exampleJWT = "\(myData)eyJ0eXAiOiJKV1"

                        try secureStore.saveItem(item: exampleJWT, itemName: myData)
                        encryptedData = exampleJWT
                    } catch {
                        print(error)
                        encryptedData = error.localizedDescription
                    }
                }
                .buttonStyle(.borderedProminent)
                .padding()

                Text(encryptedData ?? "No encrypted data")
                    .padding()
                    .background(encryptedData == "Item already exists!" ? Color.red : Color.gray)
                    .cornerRadius(10)

                Divider()
                    .padding()

                Button("Decrypt data") {
                    do {
                        let data = try secureStore.readItem(itemName: myData)
                        decryptedData = data
                    } catch {
                        print(error)
                    }
                }
                .buttonStyle(.borderedProminent).padding()

                Text(decryptedData ?? "No decrypted data")
                    .padding()
                    .background(Color.gray)
                    .cornerRadius(10)

                Divider()
                    .padding()

                HStack {
                    Button("Delete stored item") {
                        do {
                            try secureStore.deleteItem(itemName: myData)
                            encryptedData = "No encrypted data"
                            decryptedData = "No decrypted data"
                        } catch {
                            print(error)
                        }
                    }
                    .buttonStyle(.bordered)
                    .padding()

                    Button("Delete store") {
                        do {
                            try secureStore.delete()
                            encryptedData = "No encrypted data"
                            decryptedData = "No decrypted data"
                        } catch {
                            print(error)
                        }
                    }
                    .buttonStyle(.bordered)
                    .padding()
                }
            }
            .padding()
        }
    }
}
