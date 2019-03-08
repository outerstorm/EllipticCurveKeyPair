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
        try? Shared.keypair.deleteKeyPair()
        ensureKeyPair()
    }
    
    private func ensureKeyPair() {
        do {
            if !Shared.keypair.keyExists(context: context) {
                let _ = try Shared.keypair.generateKeyPair(context: context)
            }
            let key = try Shared.keypair.generateKeyPair(context: context).public.data()
            publicKeyTextView.text = key.PEM
            print(publicKeyTextView.text)
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
            self.verify(self)
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
            try Shared.keypair.verify(signature: signature, originalDigest: digest, hash: .sha512)
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

}
