import SwiftUI
import SecureStore
struct ContentView: View {
    //    myData is the string input from the user
    //    @State private var myData: String = ""
    
    @State private var encryptedData: String?
    
    @State private var decryptedData: String?
    
    let secureStore = SecureStoreService(configuration: .init(id: "wallet",
                                                              accessControlLevel: .currentBiometricsOnly))
    
    var body: some View {
        ScrollView {
            VStack {
                Button("Encrypt JWT") {
                    do {
                        
                        if try secureStore.checkItemExists(withKey: "nino-ben-2") {
                            print("item already exists!")
                            encryptedData = "Item already exists!"
                            return
                        }
                        
                        let exampleJWT = "eyJ0eXAiOiJKV1QiLCJraWQiOiJodHRwczovL3dhbGxldC1hcGkubW9iaWxlLnN0YWdpbmcuYWNjb3VudC5nb3YudWsvaG1yYy1zdHViI1RuR3c0aTVybWxxQjRNWUt0NnctcV9nLVhmNUxRTUFKaUg2bzBiYXVKOVEiLCJhbGciOiJFUzI1NiJ9.eyJjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInN1YiI6IltzdWJqZWN0IGlkZW50aWZpZXIsIGNob3NlbiBieSBobXJjXSIsImlzcyI6Imh0dHBzOi8vbW9iaWxlLnN0YWdpbmcuYWNjb3VudC5nb3YudWsvIiwiaWF0IjoxNzAxNzA4MTA1LCJleHAiOjE3MDI5MTc3MDUsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJTb2NpYWxTZWN1cml0eUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ2YWx1ZSI6Ik1zIiwidHlwZSI6IlRpdGxlIn0seyJ2YWx1ZSI6IlNhcmFoIiwidHlwZSI6IkdpdmVuTmFtZSJ9LHsidmFsdWUiOiJFbGl6YWJldGgiLCJ0eXBlIjoiR2l2ZW5OYW1lIn0seyJ2YWx1ZSI6IkVkd2FyZHMiLCJ0eXBlIjoiRmFtaWx5TmFtZSJ9XX1dLCJzb2NpYWxTZWN1cml0eVJlY29yZCI6W3sicGVyc29uYWxOdW1iZXIiOiJRUTEyMzQ1NkMifV19fX0.0Kp2SAF6ap8u8i_7gLbYGXLmIFUsx9Og54P-8kN3st9KLJim6nFfY1nYi017BeHQ1Y1AHa86ZMBAB9cDn4SXGw"
                        encryptedData = exampleJWT
                        
                        try secureStore.saveItem(item: exampleJWT, itemName: "nino-ben-2")
                    } catch {
                        print(error)
                    }
                }
                .buttonStyle(.borderedProminent).padding()
                
                Text("Encrypted data below:")
                Text(encryptedData ?? "No encrypted data")
                    .padding().background(encryptedData == "Item already exists!" ? Color.red : Color.gray).cornerRadius(10)
                
                Button("Decrypt data") {
                    do {
                        let data = try secureStore.readItem(withKey: "nino-ben-2")
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
                        try secureStore.deleteItem(keyToDelete: "nino-ben-2")
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
