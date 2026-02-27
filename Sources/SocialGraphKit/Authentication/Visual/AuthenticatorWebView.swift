//
//  AuthenticatorWebView.swift
//  SocialGraphKit
//
//  Created by User on 27/02/26. --
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

    private let subject: CurrentValueSubject<Secret?, Swift.Error> = .init(nil)

    lazy var secret: AnyPublisher<Secret, Swift.Error> = {
        subject.compactMap { $0 }.eraseToAnyPublisher()
    }()

    private var cookiesObserver: NSObjectProtocol?
    private var lastAttemptAt: TimeInterval = 0

    // MARK: - Shared WebKit Resources (Safari-like consistency)

    private static let sharedProcessPool = WKProcessPool()

    // MARK: - Init

    /// - Parameters:
    ///   - client: SocialGraphKit client instance used to build Secret.
    ///   - clearInstagramCookiesOnStart: If true, clears instagram.com cookies before auth begins.
    required init(client: Client, clearInstagramCookiesOnStart: Bool = false) {
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

        // Safari-like UA helps avoid "unsupported browser" pages.
        // WKWebView already uses Safari-like UA, but keeping a stable one helps.
        self.customUserAgent = Self.mobileSafariUserAgent()

        self.navigationDelegate = self

        // Optional: clear only instagram cookies (not the whole website data store).
        if clearInstagramCookiesOnStart {
            Self.clearInstagramCookies(in: configuration.websiteDataStore.httpCookieStore)
        }

        // Observe cookie changes instead of polling.
        startObservingCookies()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        stopObservingCookies()
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.25)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.25)
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
        attemptSecretExtraction(throttleSeconds: 0.25)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.25)
        decisionHandler(.allow)
    }

    // MARK: - Cookie Observing (Instead of polling)

    private func startObservingCookies() {
        stopObservingCookies()

        // We can't add a WKHTTPCookieStore observer directly without adopting protocol,
        // so we observe periodically via notifications pattern here:
        // - Attempt extraction on common runloop turns (navigation callbacks + this observer)
        cookiesObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.attemptSecretExtraction(throttleSeconds: 0.0)
        }
    }

    private func stopObservingCookies() {
        if let token = cookiesObserver {
            NotificationCenter.default.removeObserver(token)
            cookiesObserver = nil
        }
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

        configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] allCookies in
            guard let self else { return }
            guard self.isAuthenticating else { return }

            // Keep only relevant cookies.
            let cookies = allCookies.filter { cookie in
                cookie.domain.contains(".instagram.com") || cookie.domain.contains("instagram.com")
            }

            // Extra safety: require the core session cookies before trying Secret().
            let names = Set(cookies.map { $0.name.lowercased() })
            let hasSession = names.contains("sessionid")
            let hasUserId  = names.contains("ds_user_id")
            let hasCsrf    = names.contains("csrftoken")

            guard hasSession, hasUserId, hasCsrf else {
                return
            }

            if let secret = Secret(cookies: cookies, client: self.client) {
                self.subject.send(secret)
                self.subject.send(completion: .finished)
                self.isAuthenticating = false
            }
        }
    }
}

// MARK: - Helpers

@available(iOS 16.0, macOS 10.13, macCatalyst 13, *)
private extension AuthenticatorWebView {

    static func clearInstagramCookies(in store: WKHTTPCookieStore) {
        store.getAllCookies { cookies in
            let targets = cookies.filter { c in
                c.domain.contains(".instagram.com") || c.domain.contains("instagram.com")
            }
            targets.forEach { store.delete($0) }
        }
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
