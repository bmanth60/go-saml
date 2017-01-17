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
	"encoding/xml"
	"errors"
	"time"

	"github.com/RobotsAndPencils/go-saml/packager"
	"github.com/RobotsAndPencils/go-saml/util"
)

//Validate authentication request
func (r *AuthnRequest) Validate(publicCertPath string) error {
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	// TODO more validation

	err := packager.Verify(r.originalString, publicCertPath)
	if err != nil {
		return err
	}

	return nil
}

//GetAuthnRequest returns an authentication request object based on SAML Settings
//passed in
func GetAuthnRequest(s Settings) *AuthnRequest {
	r := NewAuthnRequest()
	r.AssertionConsumerServiceURL = s.SP.AssertionConsumerServiceURL
	r.Destination = s.IDP.SingleSignOnURL
	r.Issuer.URL = s.IDP.SingleSignOnDescriptorURL
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.SPPublicCert()
	r.NameIDPolicy.Format = s.IDP.NameIDFormat

	if !s.SP.SignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}

//NewAuthnRequest get a new authentication request object
func NewAuthnRequest() *AuthnRequest {
	id := util.ID()
	return &AuthnRequest{
		RootXML: &RootXML{
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
				URL:  "", // caller must populate ar.AppSettings.Issuer
				SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			},
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Signature: &Signature{
				XMLName: xml.Name{
					Local: "samlsig:Signature",
				},
				ID: "Signature1",
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

//String get string representation of authentication request
func (r *AuthnRequest) String() (string, error) {
	return packager.String(r)
}

//SignedString get xml signed string representation of authentication request
func (r *AuthnRequest) SignedString(privateKeyPath string) (string, error) {
	return packager.SignedString(r, privateKeyPath)
}

//EncodedSignedString get base64 encoded and xml signed string representation of authentication request
func (r *AuthnRequest) EncodedSignedString(privateKeyPath string) (string, error) {
	return packager.EncodedSignedString(r, privateKeyPath)
}

//CompressedEncodedSignedString get compressed, base64 encoded and xml signed string representation of authentication request
func (r *AuthnRequest) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	return packager.CompressedEncodedSignedString(r, privateKeyPath)
}

//EncodedString get base64 encoded string representation of authentication request object
func (r *AuthnRequest) EncodedString() (string, error) {
	return packager.EncodedString(r)
}

//CompressedEncodedString get compressed and base64 encoded string representation of authentication request object
func (r *AuthnRequest) CompressedEncodedString() (string, error) {
	return packager.CompressedEncodedString(r)
}
