package saml

import (
	"encoding/xml"
	"net/url"
	"time"

	"github.com/RobotsAndPencils/go-saml/packager"
	"github.com/RobotsAndPencils/go-saml/util"
)

//NewLogoutRequest generate new logout request entity
func NewLogoutRequest(sps ServiceProviderSettings) *LogoutRequest {
	id := util.ID()
	return &LogoutRequest{
		SAMLRoot: &SAMLRoot{
			XMLName: xml.Name{
				Local: "samlp:LogoutRequest",
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
		NameID: NameID{
			XMLName: xml.Name{
				Local: "saml:NameID",
			},
			Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
			Value:  "",
		},
	}
}

//GetLogoutRequest entity as specified by provided parameters
func GetLogoutRequest(settings SAMLSettings, nameID string, sessionIndex string) *LogoutRequest {
	r := NewLogoutRequest()
	r.Destination = settings.IDP.SingleLogoutURL
	r.Issuer.Url = settings.SP.EntityId
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = settings.SPPublicCert()
	r.NameID.Format = settings.IDP.NameIDFormat
	r.NameID.Value = nameID
	r.SessionIndex = sessionIndex

	if !settings.SP.SignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}
