//
//  SecureStore_DemoApp.swift
//  SecureStore-Demo
//
//  Created by McKillop, Ben on 04/01/2024.
//

import SwiftUI

@main
struct SecureStoreDemoApp: App {
    var body: some Scene {
        WindowGroup {
            #if DEBUG
            let isRunningTests = ProcessInfo.processInfo.environment["IS_RUNNING_TESTS"] == "1"
            if isRunningTests {
                EmptyView()
            } else {
                ContentView()
                    .navigationTitle("Secure Store - Demo")
                    .navigationBarTitleDisplayMode(.inline)
            }
            #else
            ContentView()
                .navigationTitle("Secure Store - Demo")
                .navigationBarTitleDisplayMode(.inline)
            #endif
        }
    }
}
