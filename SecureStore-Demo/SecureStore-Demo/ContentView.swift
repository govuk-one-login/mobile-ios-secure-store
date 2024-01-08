import SwiftUI
import SecureStore
struct ContentView: View {
    @State private var encryptedData: String?
    @State private var myData: String = ""
    @State private var decryptedData: String?
    
    let secureStore = SecureStoreService(configuration: .init(id: "Wallet-Test-01",
                                                              accessControlLevel: .currentBiometricsOnly))
        
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
                        
                        if try secureStore.checkItemExists(withKey: myData) {
                            print("item already exists!")
                            encryptedData = "Item already exists!"
                            return
                        }
                        
                        let exampleJWT = "\(myData)eyJ0eXAiOiJKV1QiLCJraWQiOiJodHRwczovL3dhbGxldC1hcGkubW9iaWxlLnN0YWdpbmcuYWNjb3VudC5nb3YudWsvaG1yYy1zdHViI1RuR3c0aTVybWxxQjRNWUt0NnctcV9n"
                        
                        try secureStore.saveItem(item: exampleJWT, itemName: myData)
                        encryptedData = exampleJWT
                    } catch {
                        print(error)
                        encryptedData = error.localizedDescription
                    }
                }
                .buttonStyle(.borderedProminent).padding()
                
                Text(encryptedData ?? "No encrypted data")
                    .padding().background(encryptedData == "Item already exists!" ? Color.red : Color.gray).cornerRadius(10)
                
                Divider()
                    .padding()
                
                Button("Decrypt data") {
                    do {
                        let data = try secureStore.readItem(withName: myData)
                        decryptedData = data
                    } catch {
                        print(error)
                    }
                }
                .buttonStyle(.borderedProminent).padding()
                
                Text(decryptedData ?? "No decrypted data")
                    .padding().background(Color.gray).cornerRadius(10)
                
                Divider()
                    .padding()
                
                HStack {
                    Button("Delete stored item") {
                        do {
                            try secureStore.deleteItem(keyToDelete: myData)
                            encryptedData = "No encrypted data"
                            decryptedData = "No decrypted data"
                        } catch {
                            print(error)
                        }
                    }
                    .buttonStyle(.bordered).padding()
                    
                    Button("Delete store") {
                        do {
                            try secureStore.deleteStore()
                            encryptedData = "No encrypted data"
                            decryptedData = "No decrypted data"
                        } catch {
                            print(error)
                        }
                    }
                    .buttonStyle(.bordered).padding()
                }
            }
            .padding()
        }
    }
}

#Preview {
    ContentView()
}
