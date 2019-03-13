/**
 *  Copyright (c) 2017 Håvard Fossli.
 *
 *  Licensed under the MIT license, as follows:
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

import UIKit
import LocalAuthentication
import EllipticCurveKeyPair

struct State {
    static var shared = State()
    private init() { }
    
    struct Signature {
        public var publicKey: EllipticCurveKeyPair.PublicKey
        public var digest: Data
        public var signature: Data
    }
    
    var lastSignature: Signature?
}

class SignatureViewController: UIViewController {
    
    struct Shared {
        static let keypair: EllipticCurveKeyPair.Manager = {
            EllipticCurveKeyPair.logger = { print($0) }
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: {
                return EllipticCurveKeyPair.Device.hasSecureEnclave ? [.privateKeyUsage, .applicationPassword] : [.applicationPassword]
            }())
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "no.agens.sign.public",
                privateLabel: "no.agens.sign.private",
                operationPrompt: "Sign transaction",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                token: .secureEnclaveIfAvailable)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }
    
    var context: LAContext! = LAContext()
    
    let validPassword = "testPassword"
    let invalidPassword = "someOtherPassword"
    
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureTextView: UITextView!
    @IBOutlet weak var verifyTextView: UITextView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        setValidPassword(self)
        ensureKeyPair()
    }
    
    @IBAction func regeneratePublicKey(_ sender: Any) {
        do {
            try Shared.keypair.deleteKeyPair()
        } catch {
            print("Unable to delete key pair")
        }
        ensureKeyPair()
    }
    
    private func ensureKeyPair() {
        do {
            if !Shared.keypair.keyExists(context: context) {
                let _ = try Shared.keypair.generateKeyPair(context: context)
            }
            let key = try Shared.keypair.getPublicKey().data()
            publicKeyTextView.text = key.PEM
            
            print("----\n\n\(key.DER.base64EncodedString())\n\n----")
            
            let exportData = exportECPublicKeyToDER(key.raw, keyType: EllipticCurveKeyPair.Constants.attrKeyTypeEllipticCurve, keySize: 256)
            let base64 = exportData.base64EncodedString()
            print("----\n\n\(base64)\n\n----")
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
    
    var cycleIndex = 0
    let digests = ["Lorem ipsum dolor sit amet", "mei nibh tritani ex", "exerci periculis instructior est ad"]
    
    @IBAction func createDigest(_ sender: Any) {
        cycleIndex += 1
        digestTextView.text = digests[cycleIndex % digests.count]
    }
    
    @IBAction func sign(_ sender: Any) {
        
        /*
         Using the DispatchQueue.roundTrip defined in Utils.swift is totally optional.
         What's important is that you call `sign` on a different thread than main.
         */
        
        DispatchQueue.roundTrip({
            guard let digest = self.digestTextView.text?.data(using: .utf8) else {
                throw "Missing text in unencrypted text field"
            }
            return digest
        }, thenAsync: { digest in
            return try Shared.keypair.sign(digest, hash: .sha512, context: self.context)
        }, thenOnMain: { digest, signature in
            self.signatureTextView.text = signature.base64EncodedString()
            print("Digest: \(String(describing: String(data: digest, encoding: .utf8)))")
            print("Signature: \(String(describing: self.signatureTextView.text))")
            
            print("Signature Length: \(signature.count)")
            
            self.verify(self)
            
            let pubKey = try Shared.keypair.getPublicKey()
            State.shared.lastSignature = State.Signature(publicKey: pubKey, digest: digest, signature: signature)
        }, catchToMain: { error in
            self.signatureTextView.text = "Error: \(error)"
        })
    }
    
    @IBAction func verify(_ sender: Any) {
        guard let signatureBase64 = signatureTextView.text, signatureBase64.count > 0 else {
            verifyTextView.text = "Error: No signature to verify"
            return //no signature to work with
        }
        guard let signature = Data(base64Encoded: signatureBase64) else {
            verifyTextView.text = "Error: Unable to get signature data"
            return //unable to get data from signature
        }
        guard let digestString = digestTextView.text,
            let digest = digestString.data(using: .utf8), digest.count > 0 else {
                verifyTextView.text = "Error: No digest to verify signature against"
                return //nothing to verify
        }

        do {
            let publicKey = try Shared.keypair.getPublicKey()
            try Shared.keypair.verify(signature: signature, originalDigest: digest, publicKey: publicKey, hash: .sha512)
            try printVerifySignatureInOpenssl(manager: Shared.keypair, signed: signature, digest: digest, hashAlgorithm: "sha512")
            verifyTextView.text = "Verified successfully"
        } catch {
            verifyTextView.text = "Error: \(error)"
        }
    }
    
    @IBAction func setValidPassword(_ sender: Any) {
        context.setCredential(validPassword.data(using: .utf8), type: .applicationPassword)
    }

    @IBAction func setInvalidPassword(_ sender: Any) {
        context.setCredential(invalidPassword.data(using: .utf8), type: .applicationPassword)
    }

    
    // SECP256R1 EC public key header (length + EC params (sequence) + bitstring
    private let kCryptoExportImportManagerSecp256r1CurveLen = 256
    private let kCryptoExportImportManagerSecp256r1header: [UInt8] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
    private let kCryptoExportImportManagerSecp256r1headerLen = 26
    
    private let kCryptoExportImportManagerSecp384r1CurveLen = 384
    private let kCryptoExportImportManagerSecp384r1header: [UInt8] = [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]
    private let kCryptoExportImportManagerSecp384r1headerLen = 23
    
    private let kCryptoExportImportManagerSecp521r1CurveLen = 521
    private let kCryptoExportImportManagerSecp521r1header: [UInt8] = [0x30, 0x81, 0x9B, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00]
    private let kCryptoExportImportManagerSecp521r1headerLen = 25
    
    /**
     * This function prepares a EC public key generated with Apple SecKeyGeneratePair to be exported
     * and used outisde iOS, be it openSSL, PHP, Perl, whatever. It basically adds the proper ASN.1
     * header and codifies the result as valid base64 string, 64 characters split.
     * Returns a DER representation of the key.
     */
    func exportECPublicKeyToDER(_ rawPublicKeyBytes: Data, keyType: String, keySize: Int) -> Data {
        print("Exporting EC raw key: \(rawPublicKeyBytes)")
        // first retrieve the header with the OID for the proper key  curve.
        let curveOIDHeader: [UInt8]
        let curveOIDHeaderLen: Int
        switch (keySize) {
        case kCryptoExportImportManagerSecp256r1CurveLen:
            curveOIDHeader = kCryptoExportImportManagerSecp256r1header
            curveOIDHeaderLen = kCryptoExportImportManagerSecp256r1headerLen
        case kCryptoExportImportManagerSecp384r1CurveLen:
            curveOIDHeader = kCryptoExportImportManagerSecp384r1header
            curveOIDHeaderLen = kCryptoExportImportManagerSecp384r1headerLen
        case kCryptoExportImportManagerSecp521r1CurveLen:
            curveOIDHeader = kCryptoExportImportManagerSecp521r1header
            curveOIDHeaderLen = kCryptoExportImportManagerSecp521r1headerLen
        default:
            curveOIDHeader = []
            curveOIDHeaderLen = 0
        }
        var data = Data(bytes: curveOIDHeader, count: curveOIDHeaderLen)
        
        // now add the raw data from the retrieved public key
        data.append(rawPublicKeyBytes)
        return data
    }
}
