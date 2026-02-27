#if canImport(UIKit) && canImport(WebKit)

import Foundation
import WebKit
import Combine
import UIKit

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

    private let subject: CurrentValueSubject<Secret?, Swift.Error> = .init(nil)
    lazy var secret: AnyPublisher<Secret, Swift.Error> = {
        subject.compactMap { $0 }.eraseToAnyPublisher()
    }()

    private var lastAttemptAt: TimeInterval = 0
    private var isAttemptInFlight: Bool = false
    private var attemptCount: Int = 0

    private static let sharedProcessPool = WKProcessPool()

    // MARK: - Init

    required init(client: Client) {
        let configuration = WKWebViewConfiguration()

        let prefs = WKWebpagePreferences()
        prefs.preferredContentMode = .mobile
        configuration.defaultWebpagePreferences = prefs

        configuration.websiteDataStore = .default()
        configuration.processPool = Self.sharedProcessPool

        self.client = client
        super.init(frame: .zero, configuration: configuration)

        self.customUserAgent = Self.mobileSafariUserAgent()
        self.navigationDelegate = self
        self.configuration.websiteDataStore.httpCookieStore.add(self)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit {
        configuration.websiteDataStore.httpCookieStore.remove(self)
    }

    // MARK: - Public

    func loadLogin() {
        guard let url = URL(string: "https://www.instagram.com/accounts/login/") else { return }
        var request = URLRequest(url: url)
        request.cachePolicy = .useProtocolCachePolicy
        request.timeoutInterval = 60
        request.setValue("tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7", forHTTPHeaderField: "Accept-Language")
        request.setValue("1", forHTTPHeaderField: "DNT")
        load(request)
    }

    /// Checkpoint URL’i (varsa) aynı web session içinde açmak için.
    /// Not: i.instagram.com/web/unsupported_version dönerse bu sayfa çözüm değil — kullanıcıyı www.instagram.com'a yönlendireceğiz (SGManager tarafında).
    func loadCheckpoint(_ url: URL) {
        var request = URLRequest(url: url)
        request.cachePolicy = .useProtocolCachePolicy
        request.timeoutInterval = 60
        load(request)
    }

    func resetSession() {
        Self.clearWebsiteData()
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.6)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        attemptSecretExtraction(throttleSeconds: 0.6)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard isAuthenticating else { return }

        let urlString = webView.url?.absoluteString ?? ""

        // 1) Onetap "Bilgileri kaydet" ekranı -> otomatik "Şimdi değil / Not now"
        if urlString.contains("/accounts/onetap/") {
            webView.evaluateJavaScript("""
                try {
                  const btns = Array.from(document.querySelectorAll('button'));
                  const pick = (t) => (t || '').trim().toLowerCase();
                  const target = btns.find(b => {
                    const t = pick(b.innerText);
                    return t === 'şimdi değil' || t === 'not now' || t === 'not now.' || t.includes('şimdi değil') || t.includes('not now');
                  });
                  if (target) target.click();
                } catch (_) {}
            """) { _, _ in }
        }

        // 2) Login ekranındaysa cookie consent vb. çok agresif olmayan best-effort
        if urlString.contains("/accounts/login") {
            webView.evaluateJavaScript("""
                try {
                  const buttons = Array.from(document.querySelectorAll('button'));
                  const accept = buttons.find(b => (b.innerText || '').toLowerCase().includes('allow'));
                  if (accept) accept.click();
                } catch (_) {}
            """) { _, _ in }
        }

        // Cookie hazırsa Secret üret (en doğru sinyal)
        attemptSecretExtraction(throttleSeconds: 0.0)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.6)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        attemptSecretExtraction(throttleSeconds: 0.6)
        decisionHandler(.allow)
    }

    // MARK: - WKHTTPCookieStoreObserver

    func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
        attemptSecretExtraction(throttleSeconds: 0.0)
    }

    // MARK: - Secret Extraction

    private func attemptSecretExtraction(throttleSeconds: TimeInterval) {
        guard isAuthenticating else { return }
        guard !isAttemptInFlight else { return }

        let now = Date().timeIntervalSince1970
        if throttleSeconds > 0, (now - lastAttemptAt) < throttleSeconds { return }
        lastAttemptAt = now

        attemptCount += 1
        if attemptCount > 200 { return }

        isAttemptInFlight = true
        configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] allCookies in
            guard let self else { return }
            defer { self.isAttemptInFlight = false }
            guard self.isAuthenticating else { return }

            let cookies = allCookies.filter {
                $0.domain.contains(".instagram.com") || $0.domain.contains("instagram.com")
            }

            let names = Set(cookies.map(\.name))
            let hasSession = names.contains("sessionid")
            let hasCsrf = names.contains("csrftoken")
            let hasUserId = names.contains("ds_user_id")

            guard hasSession, hasCsrf, hasUserId else { return }

            if let built = Secret(cookies: cookies, client: self.client) {
                self.subject.send(built)
                self.subject.send(completion: .finished)
                self.isAuthenticating = false
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
        let major = systemVersion.split(separator: ".").first.map(String.init) ?? "16"
        let safariVersion = "\(major).0"
        return "Mozilla/5.0 (iPhone; CPU iPhone OS \(osForCPU) like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(safariVersion) Mobile/15E148 Safari/604.1"
    }
}

#endif
