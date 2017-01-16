package saml

import (
	"github.com/RobotsAndPencils/go-saml/util"
	"github.com/RobotsAndPencils/go-saml/packager"
)

func NewLogoutRequest(sps ServiceProviderSettings) *LogoutRequest{
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

func (r *LogoutRequest) ParseCompressedEncodedRequest(b64RequestXML string) error {


	return nil
}

func (r *LogoutRequest) ParseEncodedRequest(b64RequestXML string) error {
	return nil
}

func (r *LogoutRequest) GetRequestUrl(settings ServiceProviderSettings, state string, nameID string, sessionIndex string) (string, error) {
	r.GetRequest(settings, nameID, sessionIndex)

	// Sign the request
	b64XML, err := packager.CompressedEncodedSignedStringFromKey(settings.privateKey)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(settings.IDPSingleLogoutURL)
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

func (r *LogoutRequest) GetRequest(settings ServiceProviderSettings, nameID string, sessionIndex string) *LogoutRequest {
	r.Destination = settings.IDPSingleLogoutURL
	r.Issuer.Url = settings.EntityId
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = settings.PublicCert()
	r.NameID.Format = settings.NameIDPolicyFormat
	r.NameID.Value = nameID
	r.sessionIndex = sessionIndex

	if !s.SPSignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}
