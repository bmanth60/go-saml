package saml

import (
	"encoding/xml"
	"time"

	"github.com/RobotsAndPencils/go-saml/packager"
	"github.com/RobotsAndPencils/go-saml/util"
)

//NewLogoutRequest generate new logout request entity
func NewLogoutRequest() *LogoutRequest {
	id := util.ID()
	return &LogoutRequest{
		RootXML: &RootXML{
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
				URL:  "", // caller must populate ar.AppSettings.Issuer
				SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			},
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Signature:    packager.GetSignatureEntity(id),
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
func GetLogoutRequest(settings Settings, nameID string, sessionIndex string) *LogoutRequest {
	r := NewLogoutRequest()
	r.Destination = settings.IDP.SingleLogoutURL
	r.Issuer.URL = settings.SP.EntityID
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
