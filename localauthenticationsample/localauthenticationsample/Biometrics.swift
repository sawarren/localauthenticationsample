//
//  BiometricAuthentication.swift
//  localauthenticationsample
//
//  Created by Steven Warren on 04/08/2018.
//  Copyright © 2018 conduit. All rights reserved.
//

import LocalAuthentication

typealias SecureCredentials = Biometrics.Keychain.Credentials
typealias KeychainError = Biometrics.Keychain.KeychainError

struct Biometrics {
    
    // MARK: - Biometric Authentication
    
    class Authentication {
        
        enum AuthenticationResult: Error {
            case authenticated
            case failed(reason: String)
        }
        
        private let context: LAContext
        private let reason: String
        private var policy: LAPolicy = .deviceOwnerAuthentication
        
        /// Determines whether the user must authenticate with biometrics or not.
        ///
        /// If this value is true, the user will, upon failing biometric authentication,
        /// to instead use the device passcode. If false, this option will not be granted.
        ///
        /// True by default.
        var allowsPasscodeAuthentication: Bool = true {
            didSet {
                if allowsPasscodeAuthentication {
                    policy = .deviceOwnerAuthentication
                } else {
                    policy = .deviceOwnerAuthenticationWithBiometrics
                }
            }
        }
        
        /// The title for the authentication dialog's fallback button.
        ///
        /// If the user fails to authenticate biometrically, and 'allowsPasscodeAuthentication' is true,
        /// A button with this title will be displayed allowing them to authenticate with the devices passcode.
        var fallbackTitle: String = "Use Passcode" {
            didSet {
                context.localizedFallbackTitle = fallbackTitle
            }
        }
        
        /// The title for the authentication dialog's cancel button.
        ///
        /// If pressed, it will dismiss the dialog and cancel the authentication process.
        var cancelTitle: String = "Cancel" {
            didSet {
                context.localizedCancelTitle = cancelTitle
            }
        }
        
        /// Returns an error message detailing why biometric authentication is not possible: returns nil if it is.
        fileprivate var authenticationCannotSucceed: String? {
            var error: NSError?
            if context.canEvaluatePolicy(policy, error: &error) { return nil }
            return authenticationErrorMessage(for: error as! LAError)
        }
        
        /**
         Initialises a new instance of the object.
         
         - Parameter reason: The reason authentication is being requested: This will be displayed within the authentication dialog presented to the user.
         - Parameter fallback: An optional parameter for the title of the authentication dialog's fallback button. (displayed only after failed authentication)
         - Parameter cancel: An optional parameter for the title of the authentication dialog's cancel button.
         */
        init(with reason: String, fallback: String? = nil, and cancel: String? = nil) {
            self.context = LAContext()
            self.reason = reason
            if let fallback = fallback {
                self.fallbackTitle = fallback
            }
            if let cancel = cancel {
                self.cancelTitle = cancel
            }
        }
        
        /// Request biometric authentication from the user.
        func authenticate(completion: @escaping (AuthenticationResult) -> Void) {
            if let reason = authenticationCannotSucceed {
                return completion(.failed(reason: reason))
            }
            context.evaluatePolicy(policy, localizedReason: reason) { [unowned self] success, error in
                DispatchQueue.main.async {
                    if let error = error as? LAError {
                        completion(.failed(reason: self.authenticationErrorMessage(for: error)))
                        return
                    }
                    completion(.authenticated)
                }
            }
        }
        
        // MARK: Private API
        
        fileprivate func authenticationErrorMessage(for error: LAError) -> String {
            var message = ""
            switch error.code {
            case .authenticationFailed:     message = "Authentication failed: invalid user credentials."
            case .invalidContext:           message = "Authentication failed: invalid context."
            case .notInteractive:           message = "Authentication failed: required UI cannot be displayed."
            case .userCancel:               message = "Authentication was cancelled by the user."
            case .appCancel:                message = "Authentication was cancelled by the application."
            case .systemCancel:             message = "Authentication was cancelled by the system."
            case .passcodeNotSet:           message = "Authentication failed to start. Device passcode not set."
            case .userFallback:             message = "User cancelled: chose 'fallback', but no fallback option available."
            default:                        message = policyEvaluationErrorMessage(for: error)
            }
            return message
        }
        
        fileprivate func policyEvaluationErrorMessage(for error: LAError) -> String {
            var message = ""
            if #available(iOS 11.0, *) {
                switch error.code {
                case .biometryNotAvailable: message = "This device does not support biometric authentication."
                case .biometryNotEnrolled:  message = "You have not enrolled in biometric authentication."
                case .biometryLockout:      message = "Biometry authentication locked: too many failed attempts."
                default:                    message = "Policy evaluation failed: reason unknown."
                }
            } else {
                switch error.code {
                case .touchIDNotAvailable:  message = "This device does not support biometric authentication."
                case .touchIDNotEnrolled:   message = "The user has not enrolled in biometric authentication."
                case .touchIDLockout:       message = "Biometry authentication locked: too many failed attempts."
                default:                    message = "Policy evaluation failed: reason unknown."
                }
            }
            return message
        }
    }
    
    // MARK: - Secure Keychain Access
    
    struct Keychain {
        
        struct KeychainError: Error {
            var status: OSStatus
            
            var localizedDescription: String {
                return SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error."
            }
        }
        
        struct Credentials {
            let username: String
            let password: String
        }
        
        /// Stores credentials for the given server.
        ///
        /// Credentials stored in this manner can only be retrieved after successful
        /// biometric authentication.
        static func store(credentials: Credentials, for server: String) throws {
            let account = credentials.username
            let password = credentials.password.data(using: String.Encoding.utf8)!
            
            let access = SecAccessControlCreateWithFlags(nil,
                                                         kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                         .userPresence,
                                                         nil)
            
            let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                        kSecAttrAccount as String: account,
                                        kSecAttrServer as String: server,
                                        kSecAttrAccessControl as String: access as Any,
                                        kSecValueData as String: password]
            
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else { throw KeychainError(status: status) }
        }
        
        /// Retrieves credentials for the given server.
        ///
        /// Access to these credentials is protected by Biometric authentication.
        static func credentials(for server: String) throws -> Credentials {
            let prompt = "Retrieve your credentials for '\(server)' from the keychain."
            let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                        kSecAttrServer as String: server,
                                        kSecMatchLimit as String: kSecMatchLimitOne,
                                        kSecReturnAttributes as String: true,
                                        kSecUseOperationPrompt as String: prompt,
                                        kSecReturnData as String: true]
            
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess else { throw KeychainError(status: status) }
            
            guard let existingItem = item as? [String: Any],
                let passwordData = existingItem[kSecValueData as String] as? Data,
                let password = String(data: passwordData, encoding: String.Encoding.utf8),
                let account = existingItem[kSecAttrAccount as String] as? String
                else {
                    throw KeychainError(status: errSecInternalError)
            }
            
            return Credentials(username: account, password: password)
        }
        
        /// Deletes any stored credentials for the given server.
        static func deleteCredentials(for server: String) throws {
            let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                        kSecAttrServer as String: server]
            
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess else { throw KeychainError(status: status) }
        }
    }
}


