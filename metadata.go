package saml

import (
	"encoding/xml"
	"fmt"
)

//GetEntityDescriptor get saml entity metadata XML as specified by
//http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml1x-metadata-cs-01.html
func (s *ServiceProviderSettings) GetEntityDescriptor() (string, error) {
	d := EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID: s.SP.EntityID,

		Extensions: Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",
		},
		SPSSODescriptor: SPSSODescriptor{
			AuthnRequestsSigned:        s.SP.SignRequest,
			WantAssertionsSigned:       s.SP.SignRequest,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			SigningKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "signing",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: s.SPPublicCert(),
						},
					},
				},
			},
			EncryptionKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "encryption",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: s.SPPublicCert(),
						},
					},
				},
			},
			SingleLogoutService: SingleLogoutService{
				XMLName: xml.Name{
					Local: "md:SingleLogoutService",
				},
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: s.SP.SingleLogoutServiceURL,
			},
			AssertionConsumerServices: []AssertionConsumerService{
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: s.SP.AssertionConsumerServiceURL,
					Index:    "0",
				},
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
					Location: s.SP.AssertionConsumerServiceURL,
					Index:    "1",
				},
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	return string(newMetadata), nil
}
