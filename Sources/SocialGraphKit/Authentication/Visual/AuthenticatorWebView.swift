#if canImport(UIKit) && canImport(WebKit)

import Foundation
import WebKit
import Combine
import UIKit

/// Specialized WKWebView used only for authentication.
/// It emits `Secret` only after a *validated* logged-in state.
/// If Instagram shows checkpoint/unsupported pages, it keeps the WebView alive
/// and waits for the user to complete the flow in the same session.
@available(iOS 16.0, macOS 10.13, macCatalyst 13, *)
internal final class AuthenticatorWebView: WKWebView, WKNavigationDelegate {

    // MARK: - Phase

    private enum Phase {
        case authenticating   // user is logging in / challenge screens
        case validating       // we have candidate cookies; now validating by navigating to a logged-in page
        case finished         // secret emitted
    }

    // MARK: - Properties

    private let client: Client

    /// More stable sessions by reusing same process pool (browser-like).
    private static let sharedProcessPool = WKProcessPool()

    private var phase: Phase = .authenticating {
        didSet {
            switch phase {
            case .authenticating, .validating:
                navigationDelegate = self
                isUserInteractionEnabled = true
                isHidden = false
            case .finished:
                navigationDelegate = nil
                isUserInteractionEnabled = false
                isHidden = true
            }
        }
    }

    private let semaphore: DispatchSemaphore = .init(value: 1)
    private let subject: CurrentValueSubject<Secret?, Swift.Error> = .init(nil)

    internal lazy var secret: AnyPublisher<Secret, Swift.Error> = {
        subject.compactMap { $0 }.eraseToAnyPublisher()
    }()

    private var pollTimer: Timer?
    private var lastAttemptAt: TimeInterval = 0

    /// Candidate secret (cookies exist) but not validated yet.
    private var pendingSecret: Secret?

    /// Prevent infinite validate loops.
    private var validationAttempts: Int = 0
    private let maxValidationAttempts: Int = 6

    /// If true, clears cookies/storage on init. Default false (more “real browser”).
    private let shouldClearWebsiteDataOnStart: Bool

    // MARK: - Init

    required init(client: Client, shouldClearWebsiteDataOnStart: Bool = false) {
        self.client = client
        self.shouldClearWebsiteDataOnStart = shouldClearWebsiteDataOnStart

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

        super.init(frame: .zero, configuration: configuration)

        // Safari-like UA: helps reduce "unsupported browser/version" pages.
        self.customUserAgent = Self.mobileSafariUserAgent()
        self.navigationDelegate = self

        // Clearing on every init can increase checkpoint frequency.
        if shouldClearWebsiteDataOnStart {
            Self.clearWebsiteData()
        }

        startPolling()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit { stopPolling() }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.25)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.25)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {

        // Best-effort: auto accept cookies on login screen.
        if isLoginPage(url: webView.url) {
            webView.evaluateJavaScript("""
                const btn = document.getElementsByClassName("aOOlW  bIiDR  ")?.[0];
                if (btn) btn.click();
            """) { _, _ in }
        }

        // If we were validating, decide success/fail based on final URL.
        if phase == .validating {
            handleValidationFinish(currentURL: webView.url)
        }

        attemptSecretExtraction(throttleSeconds: 0.0)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.25)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.25)
        decisionHandler(.allow)
    }

    // MARK: - Polling

    private func startPolling() {
        stopPolling()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.75, repeats: true) { [weak self] _ in
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

    // MARK: - Core Logic

    /// 1) Collect cookies -> build Secret (candidate)
    /// 2) DO NOT emit immediately
    /// 3) Validate by navigating to an authenticated page (/accounts/edit/)
    /// 4) If checkpoint/unsupported -> keep WebView, wait user
    private func attemptSecretExtraction(throttleSeconds: TimeInterval) {
        guard phase != .finished else { return }

        let now = Date().timeIntervalSince1970
        if throttleSeconds > 0, (now - lastAttemptAt) < throttleSeconds { return }
        lastAttemptAt = now

        // If currently on checkpoint/unsupported screens, do not emit or validate.
        if isCheckpointOrUnsupportedPage(url: self.url) {
            phase = .authenticating
            pendingSecret = nil
            validationAttempts = 0
            return
        }

        DispatchQueue.global(qos: .userInitiated).async { [self] in
            self.semaphore.wait()
            defer { self.semaphore.signal() }

            if self.phase == .finished { return }

            DispatchQueue.main.async { [self] in
                self.configuration.websiteDataStore.httpCookieStore.getAllCookies { [self] allCookies in

                    let cookies = allCookies.filter { cookie in
                        cookie.domain.contains(".instagram.com") || cookie.domain.contains("instagram.com")
                    }

                    guard let candidate = Secret(cookies: cookies, client: self.client) else {
                        return
                    }

                    // If already validating, just keep the pending secret.
                    self.pendingSecret = candidate

                    // Start validation if not started yet.
                    if self.phase != .validating {
                        self.beginValidation()
                    }
                }
            }
        }
    }

    /// Navigate to a page that reliably requires a logged-in session.
    /// If redirected to login/checkpoint/unsupported, validation fails and we keep WebView alive.
    private func beginValidation() {
        guard phase != .finished else { return }
        guard pendingSecret != nil else { return }

        // Avoid infinite loops.
        if validationAttempts >= maxValidationAttempts {
            phase = .authenticating
            pendingSecret = nil
            validationAttempts = 0
            return
        }

        validationAttempts += 1
        phase = .validating

        // Strong validation target
        guard let url = URL(string: "https://www.instagram.com/accounts/edit/") else { return }

        let req = URLRequest(url: url,
                             cachePolicy: .reloadIgnoringLocalCacheData,
                             timeoutInterval: 30)
        self.load(req)
    }

    private func handleValidationFinish(currentURL: URL?) {
        guard phase == .validating else { return }

        // If we landed on checkpoint/unsupported -> user must complete it; do not emit.
        if isCheckpointOrUnsupportedPage(url: currentURL) {
            phase = .authenticating
            return
        }

        // If we got redirected back to login -> not validated.
        if isLoginPage(url: currentURL) {
            phase = .authenticating
            return
        }

        // If we are still on instagram.com and not login/challenge -> treat as validated.
        // Emit final secret.
        if let finalSecret = pendingSecret {
            subject.send(finalSecret)
            subject.send(completion: .finished)
            phase = .finished
            stopPolling()
        }
    }

    // MARK: - URL helpers

    private func isLoginPage(url: URL?) -> Bool {
        guard let s = url?.absoluteString.lowercased() else { return false }
        if s.contains("/accounts/login") { return true }
        if s.contains("login") && s.contains("accounts") { return true }
        return false
    }

    private func isCheckpointOrUnsupportedPage(url: URL?) -> Bool {
        guard let s = url?.absoluteString.lowercased() else { return false }

        // Your logs show: https://i.instagram.com/web/unsupported_version/
        if s.contains("i.instagram.com/web/unsupported_version") { return true }

        // common challenge/checkpoint patterns
        if s.contains("checkpoint") { return true }
        if s.contains("challenge") { return true }
        if s.contains("two_factor") { return true }
        if s.contains("/accounts/suspended") { return true }

        return false
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
