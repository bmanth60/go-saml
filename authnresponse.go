package saml

import (
	"encoding/xml"
	"errors"
	"time"

	"github.com/RobotsAndPencils/go-saml/packager"
	"github.com/RobotsAndPencils/go-saml/util"
)

//Validate saml response
func (r *Response) Validate(s *Settings) error {
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(r.Assertion.ID) == 0 {
		return errors.New("no Assertions")
	}

	if len(r.Signature.SignatureValue.Value) == 0 && len(r.Assertion.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature")
	}

	if r.Destination != s.SP.AssertionConsumerServiceURL {
		return errors.New("destination mismath expected: " + s.SP.AssertionConsumerServiceURL + " not " + r.Destination)
	}

	if r.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.SP.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + s.SP.AssertionConsumerServiceURL + " not " + r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	err := packager.VerifyWithCert(r.originalString, s.IDP.publicCert)
	if err != nil {
		return err
	}

	//CHECK TIMES
	expires := r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	return nil
}

//NewSignedResponse get new signed response object
func NewSignedResponse() *Response {
	return &Response{
		RootXML: &RootXML{
			XMLName: xml.Name{
				Local: "samlp:Response",
			},
			SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
			ID:           util.ID(),
			Version:      "2.0",
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				URL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
			},
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
						URI: "", // caller must populate "#" + ar.Id,
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
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				// TODO unsuccesful responses??
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: Assertion{
			XMLName: xml.Name{
				Local: "saml:Assertion",
			},
			XS:           "http://www.w3.org/2001/XMLSchema",
			XSI:          "http://www.w3.org/2001/XMLSchema-instance",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			Version:      "2.0",
			ID:           util.ID(),
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameID: NameID{
					XMLName: xml.Name{
						Local: "saml:NameID",
					},
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
					Value:  "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						InResponseTo: "",
						NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339Nano),
						Recipient:    "",
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:    time.Now().Add(time.Minute * -5).UTC().Format(time.RFC3339Nano),
				NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339Nano),
			},
			AttributeStatement: AttributeStatement{
				XMLName: xml.Name{
					Local: "saml:AttributeStatement",
				},
				Attributes: []Attribute{},
			},
		},
	}
}

//AddAttribute add strong attribute to the Response
func (r *Response) AddAttribute(name, value string) {
	r.Assertion.AttributeStatement.Attributes = append(r.Assertion.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		AttributeValues: []AttributeValue{
			{
				XMLName: xml.Name{
					Local: "saml:AttributeValue",
				},
				Type:  "xs:string",
				Value: value,
			},
		},
	})
}

// GetAttribute by Name or by FriendlyName. Return blank string if not found
func (r *Response) GetAttribute(name string) string {
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}

//GetAttributeValues from attribute name or FriendlyName. Return string slice of values.
func (r *Response) GetAttributeValues(name string) []string {
	var values []string
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			for _, v := range attr.AttributeValues {
				values = append(values, v.Value)
			}
		}
	}
	return values
}

//String get string representation of authentication response object
func (r *Response) String() (string, error) {
	return packager.String(r)
}

//SignedString get xml signed string representation of authentication response object
func (r *Response) SignedString(privateKeyPath string) (string, error) {
	return packager.SignedString(r, privateKeyPath)
}

//EncodedSignedString get base64 encoded and xml signed string representation of authentication response object
func (r *Response) EncodedSignedString(privateKeyPath string) (string, error) {
	return packager.EncodedSignedString(r, privateKeyPath)
}

//CompressedEncodedSignedString get compressed, base64 encoded and xml signed string representation of authentication response object
func (r *Response) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	return packager.CompressedEncodedSignedString(r, privateKeyPath)
}
