//
//  KeyTests.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest
import SwiftyRSA

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

class PublicKeyTests: XCTestCase {
    let bundle = Bundle(for: PublicKeyTests.self)
    
    func test_initWithReference() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail()
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try PublicKey(data: data)

        let newPublicKey = try? PublicKey(reference: publicKey.reference)
        XCTAssertNotNil(newPublicKey)
    }
    
    func test_initWithReference_failsWithPrivateKey() throws {
        
        // We can't do key reference checking on iOS 8/9
        guard #available(iOS 10.0, *) else {
            return
        }
        
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try PrivateKey(pemEncoded: str)
        
        XCTAssertThrowsError(try PublicKey(reference: privateKey.reference))
    }
    
    func test_initWithData() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail()
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try? PublicKey(data: data)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithBase64String() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-base64", ofType: "txt") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithBase64StringWhichContainsNewLines() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-base64-newlines", ofType: "txt") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMName() throws {
        let publicKey = try? PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithDERName() throws {
        let publicKey = try? PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-headerless", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_publicKeysFromComplexPEMFileWorksCorrectly() {
        let input = TestUtils.pemKeyString(name: "multiple-keys-testcase")
        let keys = PublicKey.publicKeys(pemEncoded: input)
        XCTAssertEqual(keys.count, 9)
    }
    
    func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
        let keys = PublicKey.publicKeys(pemEncoded: "")
        XCTAssertEqual(keys.count, 0)
    }
    
    func test_publicKeysFromPrivateKeyPEMFileReturnsEmptyArray() {
        let input = TestUtils.pemKeyString(name: "swiftyrsa-private")
        let keys = PublicKey.publicKeys(pemEncoded: input)
        XCTAssertEqual(keys.count, 0)
    }
    
    func test_data() throws {
        
        // With header
        do {
            guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
                return XCTFail()
            }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let publicKey = try PublicKey(data: data)
            
            guard let dataFromKeychain = try? publicKey.data() else {
                return XCTFail()
            }
            
            XCTAssertNotEqual(dataFromKeychain, data)
            XCTAssertEqual(publicKey.originalData, data)
        }
        
        // Headerless
        do {
            guard let path = bundle.path(forResource: "swiftyrsa-public-headerless", ofType: "pem") else {
                return XCTFail()
            }
            let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
            let publicKey = try PublicKey(pemEncoded: str)
            XCTAssertNotNil(publicKey.originalData)
            XCTAssertNotNil(try? publicKey.data())
        }
    }
    
    func test_pemString() throws {
        let publicKey = try PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        let pemString = try publicKey.pemString()
        let newPublicKey = try PublicKey(pemEncoded: pemString)
        XCTAssertNotNil(newPublicKey)
        XCTAssertEqual(try? publicKey.data(), try? newPublicKey.data())
    }
    
    func test_base64String() throws {
        let publicKey = try PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        let base64String = try publicKey.base64String()
        let newPublicKey = try PublicKey(base64Encoded: base64String)
        XCTAssertNotNil(newPublicKey)
        XCTAssertEqual(try? publicKey.data(), try? newPublicKey.data())
    }
}

class PrivateKeyTests: XCTestCase {
    
    let bundle = Bundle(for: PublicKeyTests.self)
    
    func test_initWithReference() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try PrivateKey(pemEncoded: str)
        
        let newPrivateKey = try? PrivateKey(reference: privateKey.reference)
        XCTAssertNotNil(newPrivateKey)
    }
    
    let RAW_VALUE = "hello"
    let HASHED_VALUE = "H+UWKs9aZHM1RQFBHV9Mv+OLjsiLat+mYi/dIjHe4Ww2yixTABafDAdIBH53PnQFjGZ3ST6gNNlyZOGCrZDGp/7DwmJymOz33yseO0NpwH3nHq8Wmc1UTeWW45mZ/bEGrhYlgSzf3Z+qMbCSqn0JJJ9nKTVUOi+9mZHCSqiOOe8="
    let ENCRYPTION_PADDING_TYPE:SecPadding = .PKCS1
    let ENCRYPTED_VALUE = "tlv30tAPhlvFBriVB+R+u/8l1lL807e0A3o57KtoRoEYGEkoc2Q43V0gGv6X9OeIZzcfA0aRssWiuPPlbnTCy+Qy1UGvGSvscWQfvRL3tpg9rOOHYe+YQ3SkyqDJb2plCqP5UJGe58QqLMZJ7+Wly/BqKInKset9y3s4mIQi6Ls="
    
    func testSign() throws {
        let key = try PrivateKey(pemNamed: "swiftyrsa-private", in: Bundle(for: TestUtils.self))
        let msg = try ClearMessage(string: RAW_VALUE, using: .utf8)
        
// macOS isn't implemented yet, so this should throw
#if os(macOS)
        XCTAssertThrowsError(
            try msg.signed(with: key, digestType: .sha256)
        )
        
        return
#elseif os(iOS) || os(watchOS) || os(tvOS)
        let sig = try msg.signed(with: key, digestType: .sha256)
        let expected = try Signature(base64Encoded: HASHED_VALUE)
        
        XCTAssertEqual(
            expected.base64String,
            sig.base64String
        )
#endif
    }
    
    func testVerify() throws {
        let key = try PublicKey(pemNamed: "swiftyrsa-public", in: Bundle(for: TestUtils.self))
        let msg = try ClearMessage(string: RAW_VALUE, using: .utf8)
        let sig = try Signature(base64Encoded: HASHED_VALUE)
        
        let verification = try msg.verify(with: key, signature: sig, digestType: .sha256)
        
        XCTAssertTrue(verification.isSuccessful)
    }
    
    func testEncrypt() throws {
        let publicKey = try PublicKey(pemNamed: "swiftyrsa-public", in: Bundle(for: TestUtils.self))
        let privateKey = try PrivateKey(pemNamed: "swiftyrsa-private", in: Bundle(for: TestUtils.self))
        let msg = try ClearMessage(string: RAW_VALUE, using: .utf8)
        
        // macOS isn't implemented yet, so this should throw
        #if os(macOS)
            XCTAssertThrowsError(
                try msg.encrypted(with: publicKey, padding: ENCRYPTION_PADDING_TYPE)
            )
            
            return
        #elseif os(iOS) || os(watchOS) || os(tvOS)
            let result = try msg.encrypted(with: publicKey, padding: ENCRYPTION_PADDING_TYPE)
            
            let expected = try EncryptedMessage(base64Encoded: ENCRYPTED_VALUE)
            
            XCTAssertEqual(
                RAW_VALUE.data(using: .utf8)!,
                try expected.decrypted(with: privateKey, padding: ENCRYPTION_PADDING_TYPE).data
            )
        #endif
    }
    
    func test_initWithReference_failsWithPublicKey() throws {
        
        // We can't do key reference checking on iOS 8/9
        guard #available(iOS 10.0, *) else {
            return
        }
        
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail()
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try PublicKey(data: data)
        
        XCTAssertThrowsError(try PrivateKey(reference: publicKey.reference))
    }
    
    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? PrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }
    
    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private-headerless", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? PrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }
    
    func test_initWithPEMName() throws {
        let message = try? PrivateKey(pemNamed: "swiftyrsa-private", in: Bundle(for: TestUtils.self))
        XCTAssertNotNil(message)
    }
    
    func test_initWithDERName() throws {
        let message = try? PrivateKey(pemNamed: "swiftyrsa-private", in: Bundle(for: TestUtils.self))
        XCTAssertNotNil(message)
    }
    
    func test_data() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "der") else {
            return XCTFail()
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try PrivateKey(data: data)
        XCTAssertEqual(try? publicKey.data(), data)
    }
    
    func test_pemString() throws {
        let privateKey = try PrivateKey(pemNamed: "swiftyrsa-private", in: bundle)
        let pemString = try privateKey.pemString()
        let newPrivateKey = try PrivateKey(pemEncoded: pemString)
        XCTAssertNotNil(newPrivateKey)
        XCTAssertEqual(try? privateKey.data(), try? newPrivateKey.data())
    }
    
    func test_base64String() throws {
        let privateKey = try PrivateKey(pemNamed: "swiftyrsa-private", in: bundle)
        let base64String = try privateKey.base64String()
        let newPrivateKey = try PrivateKey(base64Encoded: base64String)
        XCTAssertEqual(try? privateKey.data(), try? newPrivateKey.data())
    }
}
