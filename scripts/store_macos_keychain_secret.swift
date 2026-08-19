import Foundation
import Security

func statusMessage(_ status: OSStatus) -> String {
    (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
}

func fail(_ message: String, code: Int32) -> Never {
    FileHandle.standardError.write(Data(("error: \(message)\n").utf8))
    exit(code)
}

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
    fail("usage: store_macos_keychain_secret <service> <account>", code: 2)
}

let service = arguments[1]
let account = arguments[2]
var secret = FileHandle.standardInput.readDataToEndOfFile()
while secret.last == 0x0A || secret.last == 0x0D {
    secret.removeLast()
}
guard !secret.isEmpty else {
    fail("standard input did not contain a secret", code: 3)
}

var trustedApplication: SecTrustedApplication?
var status = SecTrustedApplicationCreateFromPath("/usr/bin/security", &trustedApplication)
guard status == errSecSuccess, let trustedApplication else {
    fail("cannot create the trusted application: \(statusMessage(status))", code: 4)
}

var access: SecAccess?
status = SecAccessCreate(
    "Scoped 1Password service-account token" as CFString,
    [trustedApplication] as CFArray,
    &access
)
guard status == errSecSuccess, let access else {
    fail("cannot create the Keychain access rule: \(statusMessage(status))", code: 5)
}

var existingItem: SecKeychainItem?
var existingLength: UInt32 = 0
var existingData: UnsafeMutableRawPointer?
status = service.withCString { servicePointer in
    account.withCString { accountPointer in
        SecKeychainFindGenericPassword(
            nil,
            UInt32(service.utf8.count), servicePointer,
            UInt32(account.utf8.count), accountPointer,
            &existingLength, &existingData, &existingItem
        )
    }
}
if let existingData {
    SecKeychainItemFreeContent(nil, existingData)
}

if status == errSecSuccess, let existingItem {
    status = secret.withUnsafeBytes { bytes in
        SecKeychainItemModifyContent(
            existingItem,
            nil,
            UInt32(secret.count),
            bytes.baseAddress
        )
    }
    guard status == errSecSuccess else {
        fail("cannot update the Keychain item: \(statusMessage(status))", code: 6)
    }
    status = SecKeychainItemSetAccess(existingItem, access)
    guard status == errSecSuccess else {
        fail("cannot update the Keychain access rule: \(statusMessage(status))", code: 7)
    }
} else if status == errSecItemNotFound {
    var newItem: SecKeychainItem?
    status = service.withCString { servicePointer in
        account.withCString { accountPointer in
            secret.withUnsafeBytes { bytes in
                SecKeychainAddGenericPassword(
                    nil,
                    UInt32(service.utf8.count), servicePointer,
                    UInt32(account.utf8.count), accountPointer,
                    UInt32(secret.count), bytes.baseAddress!,
                    &newItem
                )
            }
        }
    }
    guard status == errSecSuccess, let newItem else {
        fail("cannot create the Keychain item: \(statusMessage(status))", code: 8)
    }
    status = SecKeychainItemSetAccess(newItem, access)
    guard status == errSecSuccess else {
        fail("cannot set the Keychain access rule: \(statusMessage(status))", code: 9)
    }
} else {
    fail("cannot inspect the Keychain item: \(statusMessage(status))", code: 10)
}

secret.resetBytes(in: 0..<secret.count)
print("stored: macOS Keychain token copy is configured")
