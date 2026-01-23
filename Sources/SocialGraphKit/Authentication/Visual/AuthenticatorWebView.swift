//
//  AuthenticatorWebView.swift
//  SocialGraphKit
//
//  Created by User on 22/01/26. - new
//

#if canImport(UIKit) && canImport(WebKit)

import Foundation
import WebKit
import Combine
import UIKit

/// Specialized WKWebView used only for authentication.
/// It emits `Secret` as soon as required cookies become available.
@available(iOS 16.0, macOS 10.13, macCatalyst 13, *)
internal final class AuthenticatorWebView: WKWebView, WKNavigationDelegate {

    // MARK: - Properties

    private let client: Client

    private var isAuthenticating: Bool = true {
        didSet {
            switch isAuthenticating {
            case true:
                navigationDelegate = self
                isUserInteractionEnabled = true
                isHidden = false
            case false:
                navigationDelegate = nil
                isUserInteractionEnabled = false
                isHidden = true
            }
        }
    }

    private let semaphore: DispatchSemaphore = .init(value: 1)
    private let subject: CurrentValueSubject<Secret?, Swift.Error> = .init(nil)

    lazy var secret: AnyPublisher<Secret, Swift.Error> = {
        subject.compactMap { $0 }.eraseToAnyPublisher()
    }()

    private var pollTimer: Timer?
    private var lastAttemptAt: TimeInterval = 0

    // MARK: - Init

    required init(client: Client) {
        let configuration = WKWebViewConfiguration()

        let prefs = WKWebpagePreferences()
        prefs.preferredContentMode = .mobile
        configuration.defaultWebpagePreferences = prefs

        configuration.websiteDataStore = .default()
        configuration.processPool = WKProcessPool()

        configuration.userContentController.addUserScript(
            .init(
                source: """
                // Best-effort UI cleanup.
                const cookieBar = document.getElementsByClassName('lOPC8 DPEif')?.[0];
                if (cookieBar) cookieBar.remove();

                const headerNotice = document.getElementById('header-notices');
                if (headerNotice) headerNotice.remove();
                """,
                injectionTime: .atDocumentEnd,
                forMainFrameOnly: true
            )
        )

        self.client = client
        super.init(frame: .zero, configuration: configuration)

        // Safari-like UA helps avoid "unsupported browser" pages.
        self.customUserAgent = Self.mobileSafariUserAgent()

        self.navigationDelegate = self

        // Clean start: prevents sticky "unsupported browser"/challenge cached states.
        Self.clearWebsiteData()

        // Start background polling (challenge / OTP screens may not redirect immediately)
        startPolling()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        stopPolling()
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.3)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.3)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard isAuthenticating else { return }

        // Best-effort: auto accept cookies on login screen.
        if webView.url?.absoluteString.contains("/accounts/login") ?? false {
            webView.evaluateJavaScript("""
                const btn = document.getElementsByClassName("aOOlW  bIiDR  ")?.[0];
                if (btn) btn.click();
            """) { _, _ in }
        }

        attemptSecretExtraction(throttleSeconds: 0.0)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.3)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.3)
        decisionHandler(.allow)
    }

    // MARK: - Polling (Critical for OTP / challenge screens)

    private func startPolling() {
        stopPolling()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.8, repeats: true) { [weak self] _ in
            self?.attemptSecretExtraction(throttleSeconds: 0.0)
        }
        RunLoop.main.add(pollTimer!, forMode: .common)
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    // MARK: - Secret Extraction

    /// Tries to build `Secret` from cookies. If it succeeds, completes publisher and stops UI.
    private func attemptSecretExtraction(throttleSeconds: TimeInterval) {
        guard isAuthenticating else { return }

        let now = Date().timeIntervalSince1970
        if throttleSeconds > 0, (now - lastAttemptAt) < throttleSeconds {
            return
        }
        lastAttemptAt = now

        DispatchQueue.global(qos: .userInitiated).async { [self] in
            self.semaphore.wait()
            guard self.isAuthenticating else { self.semaphore.signal(); return }

            DispatchQueue.main.async { [self] in
                self.configuration.websiteDataStore.httpCookieStore.getAllCookies { [self] allCookies in
                    // Keep only relevant cookies.
                    let cookies = allCookies.filter { cookie in
                        cookie.domain.contains(".instagram.com")
                        || cookie.domain.contains("instagram.com")
                    }

                    if let secret = Secret(cookies: cookies, client: self.client) {
                        // SUCCESS: emit secret and stop everything (page will "disappear" and VC can dismiss).
                        self.subject.send(secret)
                        self.subject.send(completion: .finished)
                        self.isAuthenticating = false
                        self.stopPolling()
                        self.semaphore.signal()
                        return
                    }

                    // Not ready yet -> keep polling / next navigation will try again.
                    self.semaphore.signal()
                }
            }
        }
    }
}

// MARK: - Helpers

@available(iOS 16.0, macOS 10.13, macCatalyst 13, *)
private extension AuthenticatorWebView {

    static func clearWebsiteData() {
        let dataStore = WKWebsiteDataStore.default()
        let types: Set<String> = [
            WKWebsiteDataTypeCookies,
            WKWebsiteDataTypeLocalStorage,
            WKWebsiteDataTypeSessionStorage,
            WKWebsiteDataTypeIndexedDBDatabases,
            WKWebsiteDataTypeWebSQLDatabases,
            WKWebsiteDataTypeDiskCache,
            WKWebsiteDataTypeMemoryCache
        ]

        dataStore.removeData(ofTypes: types, modifiedSince: Date(timeIntervalSince1970: 0)) { }
    }

    static func mobileSafariUserAgent() -> String {
        let systemVersion = UIDevice.current.systemVersion
        let osForCPU = systemVersion.replacingOccurrences(of: ".", with: "_")

        let versionComponents = systemVersion.split(separator: ".")
        let major = versionComponents.first.map(String.init) ?? "16"
        let minor = versionComponents.dropFirst().first.map(String.init) ?? "0"
        let safariVersion = "\(major).\(minor)"

        return "Mozilla/5.0 (iPhone; CPU iPhone OS \(osForCPU) like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(safariVersion) Mobile/15E148 Safari/604.1"
    }
}

#endif
