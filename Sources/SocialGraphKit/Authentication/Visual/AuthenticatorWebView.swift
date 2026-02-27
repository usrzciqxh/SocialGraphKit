//
//  AuthenticatorWebView.swift
//  SocialGraphKit
//
//  Created by User on 27/02/26. - new
//

#if canImport(UIKit) && canImport(WebKit)

import Foundation
import WebKit
import Combine
import UIKit

/// Specialized WKWebView used only for authentication.
/// It emits `Secret` as soon as required cookies become available.
///
/// Goals:
/// - Behave more like a real Safari session (persisted process pool, avoid aggressive clearing/polling)
/// - Extract cookies reliably with observer (less "bot-like" than tight polling)
/// - Keep existing public surface area (publisher-based Secret emission)
@available(iOS 16.0, macOS 10.13, macCatalyst 13, *)
internal final class AuthenticatorWebView: WKWebView, WKNavigationDelegate, WKHTTPCookieStoreObserver {

    // MARK: - Properties

    private let client: Client

    private var isAuthenticating: Bool = true {
        didSet {
            if isAuthenticating {
                navigationDelegate = self
                isUserInteractionEnabled = true
                isHidden = false
            } else {
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

    private var lastAttemptAt: TimeInterval = 0

    // MARK: - Shared “Safari-like” components

    /// Using a shared process pool makes the web session behave closer to Safari
    /// (cookies/storage continuity across WKWebView instances within the app process).
    private static let sharedProcessPool = WKProcessPool()

    // MARK: - Init

    required init(client: Client) {
        let configuration = WKWebViewConfiguration()

        let prefs = WKWebpagePreferences()
        prefs.preferredContentMode = .mobile
        configuration.defaultWebpagePreferences = prefs

        // Persistent store (Safari-like)
        configuration.websiteDataStore = .default()

        // IMPORTANT: shared process pool (Safari-like)
        configuration.processPool = Self.sharedProcessPool

        // Keep JS enabled (default), but explicit is fine.
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true

        // Lightweight UI cleanup (best-effort; should not affect auth flow)
        configuration.userContentController.addUserScript(
            .init(
                source: """
                try {
                  const cookieBar = document.getElementsByClassName('lOPC8 DPEif')?.[0];
                  if (cookieBar) cookieBar.remove();

                  const headerNotice = document.getElementById('header-notices');
                  if (headerNotice) headerNotice.remove();
                } catch (_) {}
                """,
                injectionTime: .atDocumentEnd,
                forMainFrameOnly: true
            )
        )

        self.client = client
        super.init(frame: .zero, configuration: configuration)

        // More Safari-like UA (avoid "unsupported browser" pages).
        // NOTE: This is still "web" UA (Safari). That’s intentional for WebView login.
        self.customUserAgent = Self.mobileSafariUserAgent()

        self.navigationDelegate = self

        // Observe cookie updates instead of aggressive polling.
        self.configuration.websiteDataStore.httpCookieStore.add(self)

        // Don’t clear website data on every init.
        // Clearing at every init can look suspicious and also breaks continuity.
        //
        // If you really need a "hard reset", call `resetSession()` from outside explicitly.
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        configuration.websiteDataStore.httpCookieStore.removeObserver(self)
    }

    // MARK: - Public helpers

    /// Load Instagram login in a slightly more "real browser" way (request headers).
    /// Call this from your VC after creating the view.
    func loadLogin() {
        guard let url = URL(string: "https://www.instagram.com/accounts/login/") else { return }
        var request = URLRequest(url: url)
        request.cachePolicy = .useProtocolCachePolicy
        request.timeoutInterval = 60

        // These headers are "webby" and harmless; WKWebView may ignore some,
        // but sending them on initial request helps mimic normal navigation.
        request.setValue("tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7", forHTTPHeaderField: "Accept-Language")
        request.setValue("1", forHTTPHeaderField: "DNT")
        request.setValue("max-age=0", forHTTPHeaderField: "Cache-Control")
        request.setValue("no-cache", forHTTPHeaderField: "Pragma")

        load(request)
    }

    /// If you want a hard reset (manual).
    func resetSession() {
        Self.clearWebsiteData()
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.5)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.5)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard isAuthenticating else { return }

        // Best-effort cookie consent click (may change over time; safe to ignore errors).
        if webView.url?.absoluteString.contains("/accounts/login") ?? false {
            webView.evaluateJavaScript("""
                try {
                  const btn =
                    document.querySelector('button:has(div:contains("Allow all cookies"))') ||
                    document.getElementsByClassName("aOOlW  bIiDR  ")?.[0];
                  if (btn) btn.click();
                } catch (_) {}
            """) { _, _ in }
        }

        attemptSecretExtraction(throttleSeconds: 0.0)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.5)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.5)
        decisionHandler(.allow)
    }

    // MARK: - WKHTTPCookieStoreObserver

    func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
        // Cookie changes are the most reliable signal that login completed.
        attemptSecretExtraction(throttleSeconds: 0.0)
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
            semaphore.wait()
            defer { semaphore.signal() }

            guard isAuthenticating else { return }

            DispatchQueue.main.async { [self] in
                configuration.websiteDataStore.httpCookieStore.getAllCookies { [self] allCookies in

                    let cookies = allCookies.filter { cookie in
                        cookie.domain.contains(".instagram.com") || cookie.domain.contains("instagram.com")
                    }

                    // Minimal sanity check: wait for key cookies we expect after successful web login.
                    // (This prevents emitting a Secret too early.)
                    let names = Set(cookies.map(\.name))
                    let hasSession = names.contains("sessionid")
                    let hasCsrf = names.contains("csrftoken")
                    let hasUserId = names.contains("ds_user_id")

                    guard hasSession, hasCsrf, hasUserId else {
                        return
                    }

                    if let built = Secret(cookies: cookies, client: self.client) {
                        subject.send(built)
                        subject.send(completion: .finished)

                        isAuthenticating = false
                        return
                    }
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

    /// A conservative Safari-like UA.
    /// (We intentionally keep this "web" UA for WebView login.)
    static func mobileSafariUserAgent() -> String {
        let systemVersion = UIDevice.current.systemVersion
        let osForCPU = systemVersion.replacingOccurrences(of: ".", with: "_")

        // Keep Version/<major>.0 format (Safari-like)
        let major = systemVersion.split(separator: ".").first.map(String.init) ?? "16"
        let safariVersion = "\(major).0"

        return "Mozilla/5.0 (iPhone; CPU iPhone OS \(osForCPU) like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(safariVersion) Mobile/15E148 Safari/604.1"
    }
}

#endif
