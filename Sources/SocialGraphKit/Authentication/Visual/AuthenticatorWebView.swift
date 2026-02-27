//
//  AuthenticatorWebView.swift
//  SocialGraphKit
//
//  Created by User on 27/02/26.
//

#if canImport(UIKit) && canImport(WebKit)

import Foundation
import WebKit
import Combine
import UIKit

/// Specialized WKWebView used only for authentication.
/// It emits `Secret` only when session cookies are truly ready (sessionid + ds_user_id + csrftoken).
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

    // MARK: - Config knobs (keep web-like)

    /// Keep it "Safari-like": do NOT wipe cookies/storage on each init.
    private static let shouldClearWebsiteDataOnInit: Bool = false

    /// WKProcessPool should be shared to avoid "new browser instance" fingerprint on every init.
    private static let sharedProcessPool = WKProcessPool()

    /// Polling is useful for challenge screens, but too aggressive polling can look suspicious.
    private static let pollInterval: TimeInterval = 1.25

    /// Some setups benefit from forcing a Safari-like UA, some do not.
    /// Default: use WKWebView’s own UA (most web-like on iOS).
    private static let shouldOverrideUserAgent: Bool = false

    /// We only emit secret when these cookies exist.
    private static let requiredCookieNames: Set<String> = ["sessionid", "ds_user_id", "csrftoken"]

    // MARK: - Init

    required init(client: Client) {
        let configuration = WKWebViewConfiguration()

        let prefs = WKWebpagePreferences()
        prefs.preferredContentMode = .mobile
        configuration.defaultWebpagePreferences = prefs

        configuration.websiteDataStore = .default()
        configuration.processPool = Self.sharedProcessPool

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

        if Self.shouldOverrideUserAgent {
            self.customUserAgent = Self.mobileSafariUserAgent()
        }

        self.navigationDelegate = self

        if Self.shouldClearWebsiteDataOnInit {
            Self.clearWebsiteData()
        }

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
        attemptSecretExtraction(throttleSeconds: 0.35)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.35)
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
        attemptSecretExtraction(throttleSeconds: 0.35)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.35)
        decisionHandler(.allow)
    }

    // MARK: - Polling

    private func startPolling() {
        stopPolling()
        pollTimer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            self?.attemptSecretExtraction(throttleSeconds: 0.0)
        }
        if let pollTimer {
            RunLoop.main.add(pollTimer, forMode: .common)
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    // MARK: - Secret Extraction

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
                let cookieStore = self.configuration.websiteDataStore.httpCookieStore
                cookieStore.getAllCookies { [self] allCookies in

                    // Keep only relevant cookies.
                    let igCookies = allCookies.filter { cookie in
                        cookie.domain.contains(".instagram.com")
                        || cookie.domain.contains("instagram.com")
                    }

                    // Gate: ensure session cookies exist (prevents early/unstable secret).
                    if !Self.hasRequiredCookies(in: igCookies) {
                        self.semaphore.signal()
                        return
                    }

                    // Optional extra gate: we prefer not to emit while still on /accounts/login
                    // because session may not be fully settled yet.
                    if let url = self.url?.absoluteString,
                       url.contains("/accounts/login") {
                        self.semaphore.signal()
                        return
                    }

                    if let secret = Secret(cookies: igCookies, client: self.client) {
                        self.subject.send(secret)
                        self.subject.send(completion: .finished)

                        self.isAuthenticating = false
                        self.stopPolling()

                        self.semaphore.signal()
                        return
                    }

                    self.semaphore.signal()
                }
            }
        }
    }
}

// MARK: - Helpers

@available(iOS 16.0, macOS 10.13, macCatalyst 13, *)
private extension AuthenticatorWebView {

    static func hasRequiredCookies(in cookies: [HTTPCookie]) -> Bool {
        let names = Set(cookies.map { $0.name.lowercased() })
        for req in requiredCookieNames {
            if !names.contains(req) { return false }
        }
        return true
    }

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
