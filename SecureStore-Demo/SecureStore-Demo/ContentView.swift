import SwiftUI
import SecureStore
struct ContentView: View {
    //    myData is the string input from the user
    //    @State private var myData: String = ""
    
    @State private var encryptedData: String?
    
    @State private var decryptedData: String?
    
    let secureStore = SecureStoreService(configuration: .init(id: "Wallet-Test-01",
                                                              accessControlLevel: .currentBiometricsOnly))
    
    @State private var myData: String = ""
    
    var body: some View {
        ScrollView {
            VStack {
                
                TextField("Input your data", text: $myData)
                    .textFieldStyle(.roundedBorder)
                    .multilineTextAlignment(.center)
                    .fixedSize()
                
                Button("Encrypt JWT") {
                    do {
                        encryptedData = ""
                        
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
                
                Text("Encrypted data below:")
                Text(encryptedData ?? "No encrypted data")
                    .padding().background(encryptedData == "Item already exists!" ? Color.red : Color.gray).cornerRadius(10)
                
                Button("Decrypt data") {
                    do {
                        let data = try secureStore.readItem(withName: myData)
                        decryptedData = data
                    } catch {
                        print(error)
                    }
                }
                .buttonStyle(.borderedProminent).padding()
                
                Text("Decrypted data below:")
                Text(decryptedData ?? "No decrypted data")
                    .padding().background(Color.gray).cornerRadius(10)
                
                Button("Delete stored data") {
                    do {
                        try secureStore.deleteItem(keyToDelete: myData)
                        encryptedData = ""
                        decryptedData = ""
                    } catch {
                        print(error)
                    }
                }
                .buttonStyle(.bordered).padding()
            }
            .padding()
        }
    }
}

#Preview {
    ContentView()
}
