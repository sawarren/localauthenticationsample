//
//  SampleViewController.swift
//  localauthenticationsample
//
//  Created by Steven Warren on 03/08/2018.
//  Copyright © 2018 conduit. All rights reserved.
//

import UIKit

class SampleViewController: UIViewController {
    
    // MARK: Variables
    
    @IBOutlet fileprivate weak var mainStackView: UIStackView!
    
    @IBOutlet fileprivate weak var credentialsStackView: UIStackView!
    @IBOutlet fileprivate weak var usernameTextField: UITextField!
    @IBOutlet fileprivate weak var passwordTextField: UITextField!
    @IBOutlet fileprivate weak var storeButton: UIButton!
    @IBOutlet fileprivate weak var retrieveButton: UIButton!
    @IBOutlet fileprivate weak var deleteButton: UIButton!
    
    @IBOutlet fileprivate weak var loginButton: UIButton!
    @IBOutlet fileprivate weak var logoutButton: UIButton!
    
    @IBOutlet fileprivate weak var statusLabel: UILabel!
    
    fileprivate let server = "localauthentication.sample.com"
    fileprivate var authenticated = false
    fileprivate var credentialsFormCompleted: Bool {
        guard let username = usernameTextField.text,
            let password = passwordTextField.text
            else {
                return false
        }
        return username.count > 0 && password.count > 0
    }

    // MARK: Life cycle
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupViews()
        try? Biometrics.Keychain.deleteCredentials(for: server)
    }
    
    // MARK: Setup
    
    fileprivate func setupViews() {
        let padding: CGFloat = 8.0
        mainStackView.isLayoutMarginsRelativeArrangement = true
        mainStackView.layoutMargins = UIEdgeInsets(top: padding, left: padding, bottom: padding, right: padding)
        usernameTextField.delegate = self
        passwordTextField.delegate = self
        updateViewState(animated: false)
    }

    // MARK: Actions
    
    @IBAction fileprivate func loginButtonTouchUpInside(_ sender: UIButton? = nil) {
        requestBiometricAuthentication()
    }
    
    @IBAction fileprivate func logoutTouchUpInside(_ sender: UIButton) {
        authenticated = false
        updateViewState()
    }
    
    @IBAction fileprivate func keychainButtonsTouchUpInside(_ sender: UIButton) {
        switch sender {
        case storeButton:
            guard credentialsFormCompleted else {
                updateStatus(with: "Please provide credentials for secure storage.", and: .red)
                return
            }
            storeCredentials()
            clearCredentialsForm()
        case retrieveButton:
            if let credentials = retrieveCredentials() {
                let text = """
                credentials retrieved.
                username = \(credentials.username)
                password = \(credentials.password)
                """
                updateStatus(with: text)
            }
        case deleteButton:
            deleteCredentials()
        default:
            break
        }
    }

    // MARK: Helpers

    fileprivate func updateStatus(with text: String, and color: UIColor? = .black) {
        statusLabel.text = text
        statusLabel.textColor = color
    }
    
    fileprivate func clearCredentialsForm() {
        usernameTextField.text = ""
        passwordTextField.text = ""
    }
}

// MARK: - Biometrics

extension SampleViewController {
    
    fileprivate func requestBiometricAuthentication() {
        let reason = "Log in to access stored keychain information"
        let authentication = Biometrics.Authentication(with: reason)
        authentication.fallbackTitle = "I'd rather use my passcode"
        authentication.cancelTitle = "No thanks"
        authentication.authenticate { result in
            switch result {
            case .authenticated:
                self.authenticated = true
                self.updateViewState()
            case .failed(let reason):
                self.updateStatus(with: reason, and: .red)
            }
        }
    }
    
    fileprivate func storeCredentials() {
        do {
            let credentials = SecureCredentials(username: usernameTextField.text!, password: passwordTextField.text!)
            try Biometrics.Keychain.store(credentials: credentials, for: server)
            updateStatus(with: "credentials stored.", and: .green)
        } catch {
            if let error = error as? KeychainError {
                updateStatus(with: error.localizedDescription, and: .red)
            }
        }
    }
    
    fileprivate func retrieveCredentials() -> SecureCredentials? {
        do {
            return try Biometrics.Keychain.credentials(for: server)
        } catch {
            if let error = error as? KeychainError {
                updateStatus(with: error.localizedDescription, and: .red)
            }
        }
        return nil
    }
    
    fileprivate func deleteCredentials() {
        do {
            try Biometrics.Keychain.deleteCredentials(for: server)
            updateStatus(with: "credentials deleted.", and: .green)
        } catch {
            if let error = error as? KeychainError {
                updateStatus(with: error.localizedDescription, and: .red)
            }
        }
    }
}

// MARK: - UITextFieldDelegate

extension SampleViewController: UITextFieldDelegate {
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        if textField == usernameTextField {
            passwordTextField.becomeFirstResponder()
        } else if textField == passwordTextField {
            passwordTextField.resignFirstResponder()
        }
        return false
    }
}

// MARK: - UI & Animation

extension SampleViewController {
    fileprivate func updateViewState(animated: Bool = true) {
        let targetAlpha: CGFloat = authenticated ? 1 : 0
        let updates = {
            if self.authenticated {
                self.updateStatus(with: "authentication successful.", and: .green)
            } else {
                self.updateStatus(with: "Please authenticate to access secure keychain functionality.")
            }
            self.loginButton.isHidden = self.authenticated
            self.credentialsStackView.isHidden = !self.authenticated
            self.logoutButton.alpha = targetAlpha
            self.view.layoutIfNeeded()
        }
        guard animated else { return updates() }
        UIView.animate(withDuration: 0.25, delay: 0, usingSpringWithDamping: 0.9, initialSpringVelocity: 0.1, options: .curveEaseInOut, animations: updates)
    }
}









