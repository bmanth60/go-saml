// Copyright 2014 Matthew Baird, Andrew Mussey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net/url"
	"time"

	"github.com/RobotsAndPencils/go-saml/util"
	"github.com/RobotsAndPencils/go-saml/packager"
)

func ParseCompressedEncodedRequest(b64RequestXML string) (*AuthnRequest, error) {
	var authnRequest AuthnRequest
	compressedXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)

	err = xml.Unmarshal(bXML, &authnRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnRequest.originalString = string(bXML)
	return &authnRequest, nil

}

func ParseEncodedRequest(b64RequestXML string) (*AuthnRequest, error) {
	authnRequest := AuthnRequest{}
	bytesXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	err = xml.Unmarshal(bytesXML, &authnRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnRequest.originalString = string(bytesXML)
	return &authnRequest, nil
}

func (r *AuthnRequest) Validate(publicCertPath string) error {
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	// TODO more validation

	err := Verify(r.originalString, publicCertPath)
	if err != nil {
		return err
	}

	return nil
}

// GetSignedAuthnRequest returns a signed XML document that represents an AuthnRequest SAML document
func (s *ServiceProviderSettings) GetAuthnRequest() *AuthnRequest {
	r := NewAuthnRequest()
	r.AssertionConsumerServiceURL = s.AssertionConsumerServiceURL
	r.Destination = s.IDPSSOURL
	r.Issuer.Url = s.IDPSSODescriptorURL
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.PublicCert()

	if !s.SPSignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequest parameter encoded
func GetAuthnRequestURL(baseURL string, b64XML string, state string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// GetSignedAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequest parameter encoded
func GetSignedAuthnRequestURL(settings ServiceProviderSettings, state string) (string, error) {
	r := settings.GetAuthnRequest()
	r.NameIDPolicy.Format = settings.NameIDPolicyFormat

	// Sign the request
	b64XML, err := r.CompressedEncodedSignedStringFromKey(settings.privateKey)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(settings.IDPSSOURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)
	q.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

	//Build signature string. Digest must be in this order.
	sigstr := "SAMLRequest=" + url.QueryEscape(q.Get("SAMLRequest")) +
		"&RelayState=" + url.QueryEscape(q.Get("RelayState")) +
		"&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))

	sig, err := GetRequestSignature(sigstr, settings.privateKey)
	if err != nil {
		return "", err
	}

	q.Set("Signature", sig)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func GetRequestSignature(data string, key string) (sig string, err error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", errors.New("Certificate not valid pem format")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes) //x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	digest := sha1.Sum([]byte(data))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

func NewAuthnRequest() *AuthnRequest {
	id := util.ID()
	return &AuthnRequest{
		SAMLRoot: &SAMLRoot{
			XMLName: xml.Name{
				Local: "samlp:AuthnRequest",
			},
			SAMLP:   "urn:oasis:names:tc:SAML:2.0:protocol",
			SAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
			SAMLSIG: "http://www.w3.org/2000/09/xmldsig#",
			ID:      id,
			Version: "2.0",
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				Url:  "", // caller must populate ar.AppSettings.Issuer
				SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			},
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Signature: &Signature{
				XMLName: xml.Name{
					Local: "samlsig:Signature",
				},
				Id: "Signature1",
				SignedInfo: SignedInfo{
					XMLName: xml.Name{
						Local: "samlsig:SignedInfo",
					},
					CanonicalizationMethod: CanonicalizationMethod{
						XMLName: xml.Name{
							Local: "samlsig:CanonicalizationMethod",
						},
						Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
					},
					SignatureMethod: SignatureMethod{
						XMLName: xml.Name{
							Local: "samlsig:SignatureMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
					},
					SamlsigReference: SamlsigReference{
						XMLName: xml.Name{
							Local: "samlsig:Reference",
						},
						URI: "#" + id,
						Transforms: Transforms{
							XMLName: xml.Name{
								Local: "samlsig:Transforms",
							},
							Transform: Transform{
								XMLName: xml.Name{
									Local: "samlsig:Transform",
								},
								Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
							},
						},
						DigestMethod: DigestMethod{
							XMLName: xml.Name{
								Local: "samlsig:DigestMethod",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
						},
						DigestValue: DigestValue{
							XMLName: xml.Name{
								Local: "samlsig:DigestValue",
							},
						},
					},
				},
				SignatureValue: SignatureValue{
					XMLName: xml.Name{
						Local: "samlsig:SignatureValue",
					},
				},
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "samlsig:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "samlsig:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "samlsig:X509Certificate",
							},
							Cert: "", // caller must populate cert,
						},
					},
				},
			},
		},
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: &RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
}

func (r *AuthnRequest) String() (string, error) {
	return packager.String(r)
}

func (r *AuthnRequest) SignedString(privateKeyPath string) (string, error) {
	return packager.SignedString(r, privateKeyPath)
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequst parameter encoded
func (r *AuthnRequest) EncodedSignedString(privateKeyPath string) (string, error) {
	return packager.EncodedSignedString(r, privateKeyPath)
}

//CompressedEncodedSignedStringFromKey sign string with sp key, compress, then base64 encode
func (r *AuthnRequest) CompressedEncodedSignedStringFromKey(key string) (string, error) {
	return packager.CompressedEncodedSignedStringFromKey(r, key)
}

func (r *AuthnRequest) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	return packager.CompressedEncodedSignedString(r, privateKeyPath)
}

func (r *AuthnRequest) EncodedString() (string, error) {
	return packager.EncodedString(r)
}

func (r *AuthnRequest) CompressedEncodedString() (string, error) {
	return packager.CompressedEncodedString(r)
}
