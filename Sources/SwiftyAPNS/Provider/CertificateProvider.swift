//
//  CertificateProvider.swift
//  SwiftyAPNS
//
//  Created by Sergii Tkachenko on 11.08.2020.
//  Copyright © 2020 Sergii Tkachenko. All rights reserved.
//

import Foundation

internal final class APNSCertificateProvider: NSObject, APNSSendMessageProtocol {
    
    private var identity: SecIdentity
    private var session: URLSession = URLSession.shared
    
    private static let decoder = JSONDecoder()
    
    public init(identity: SecIdentity, sandbox: Bool = true, configuration: URLSessionConfiguration = URLSessionConfiguration.default) {
        self.identity = identity
        super.init()
        // HTTP/2 사용 강제
        configuration.protocolClasses = []  // 기본 프로토콜 클래스 제거
        configuration.httpMaximumConnectionsPerHost = 1
        configuration.timeoutIntervalForRequest = 30
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData

        // ALPN을 통해 HTTP/2 협상 활성화
        if #available(macOS 10.13, *) {
            configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        }
        self.session = URLSession.init(configuration: configuration, delegate: self, delegateQueue: nil)
    }
    
    public func push<P: Payloadable>(_ notification: APNSNotification<P>) async throws -> APNSResponse {
        let request = try APNSRequestFactory.makeRequest(notification)
        let (data, response) = try await session.data(for: request)
        if let responce = response as? HTTPURLResponse,
           let apnsStatus = APNSStatus(code: responce.statusCode),
           let apnsId = responce.allHeaderFields["apns-id"] as? String {
            let reason = try? Self.decoder.decode(APNSError.self, from: data)
            return APNSResponse(status: apnsStatus, apnsId: apnsId, reason: reason)
        } else {
            throw APNSProviderError.parseResponce
        }
    }
}

extension APNSCertificateProvider: URLSessionDelegate {
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        if let error = error {
            print("APNS session error: \(error)")
        }
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Swift.Void) {
        var certificate: SecCertificate?
        _ = withUnsafeMutablePointer(to: &certificate) {
            SecIdentityCopyCertificate(identity, UnsafeMutablePointer($0))
        }
        
        var certificates = [SecCertificate]()
        if let certificate = certificate {
            certificates.append(certificate)
        }
        
        let credential = URLCredential.init(identity: self.identity, certificates: certificates, persistence: .forSession)
        completionHandler(.useCredential, credential)
    }
}
