//
//  VerifyViewController.swift
//  EllipticCurveKeyPair
//
//  Created by Justin Storm on 3/11/19.
//

import UIKit
import EllipticCurveKeyPair
import LocalAuthentication

class VerifyViewController: UIViewController {
    
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureTextView: UITextView!
    @IBOutlet weak var verifyTextView: UITextView!
    @IBOutlet weak var verifyButton: UIButton!
    
    private var publicKey: EllipticCurveKeyPair.PublicKey?
    
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
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // ------- THESE ARE TEST VALUES FOR VERIFYING EXTERNAL SIGNATURES ------
        /*
        if let pubKey = getPublicKey(fromBase64DER: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1khSvAdw7KIuQCgGQlhMLY2qgTv6RFCKVScyMKOMI3chuqn8IspeA7gc5Kp4PyDg0eGYAG74ZP3TDRuGYLP/sg=="),
            let digest = "Lorem ipsum dolor sit amet".data(using: .utf8),
            let signature = Data(base64Encoded: "MEYCIQDyIuUN60mYqPocukUJhwQzkJ66GbUmmMh9Egp3exp0MgIhAPqX1VgefB5mHLk7FGllyUu4+iHxyDXAv2D+HIPn7t2k") {
                State.shared.lastSignature = State.Signature(publicKey: pubKey, digest: digest, signature: signature)
        }
        */
        
        guard let lastSignature = State.shared.lastSignature,
            lastSignature.digest.count > 0, lastSignature.signature.count > 0 else {
            
                let error = "ERROR: Invalid Signature Data"
                publicKeyTextView.text = error
                digestTextView.text = error
                signatureTextView.text = error
                verifyTextView.text = error
                verifyButton.isEnabled = false
                
                return
        }
        
        importPublicKey(from: lastSignature)
        digestTextView.text = String(data: lastSignature.digest, encoding: .utf8)
        signatureTextView.text = lastSignature.signature.base64EncodedString()
    }
    
    @IBAction func verify(_ sender: Any) {
        guard let signatureData = Data(base64Encoded: signatureTextView.text), signatureData.count > 0 else {
            verifyTextView.text = "ERROR: Unable to get signature data"
            return
        }
        guard let digestData = digestTextView.text.data(using: .utf8), digestData.count > 0 else {
            verifyTextView.text = "ERROR: Unable to get digest data"
            return
        }
        guard let publicKey = publicKey else {
            verifyTextView.text = "ERROR: Unable to get public key"
            return
        }
        
        do {
            try Shared.keypair.verify(signature: signatureData, originalDigest: digestData, publicKey: publicKey, hash: .sha512)
            
            print("Verified Successfully!")
            
            verifyTextView.text = "Verified Successfully!"
        } catch {
            verifyTextView.text = "ERROR: \(error)"
        }
    }
    
    private func getPublicKey(fromBase64DER base64DER: String) -> EllipticCurveKeyPair.PublicKey? {
        guard let data = Data(base64Encoded: base64DER) else {
            return nil
        }
        guard let secKey = SecKey.publicKeyFromDERData(data) else {
            print("ERROR: Unable to create SecKey from server key data")
            return nil
        }
        return EllipticCurveKeyPair.PublicKey(secKey)
    }
    
    private func importPublicKey(from signature: State.Signature) {
        var serverKey: String
        do {
            serverKey = try signature.publicKey.data().DER.base64EncodedString()
        } catch {
            publicKeyTextView.text = "ERROR: Unable to import public key"
            return
        }

        publicKey = getPublicKey(fromBase64DER: serverKey)
        guard publicKey != nil else {
            publicKeyTextView.text = "ERROR: Unable to get public key from base64 DER"
            return
        }
        
        do {
            publicKeyTextView.text = try publicKey?.data().PEM
            verifyButton.isEnabled = true
        } catch {
            publicKeyTextView.text = "ERROR: \(error)"
            verifyButton.isEnabled = false
        }
    }
}
