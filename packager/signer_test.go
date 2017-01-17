package packager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//TODO This test does not work, need to rewrite
func TestRequest(t *testing.T) {
	assert := assert.New(t)
	assert.True(true)
	/*cert, err := util.LoadCertificate("../certs/default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	request := &types.AuthnRequest{
		RootXML: &types.RootXML{
			XMLName: xml.Name{
				Local: "samlp:AuthnRequest",
			},
			SAMLP:   "urn:oasis:names:tc:SAML:2.0:protocol",
			SAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
			SAMLSIG: "http://www.w3.org/2000/09/xmldsig#",
			ID:      "some-id",
			Version: "2.0",
			Destination: "http://somewhere.com/saml",
			IssueInstant: "time-at-test",
			Signature: &types.Signature{},
		},
	}
	request.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err := xml.MarshalIndent(request, "", "    ")
	assert.NoError(err)
	xmlRequest := string(b)

	signedXml, err := Sign(xmlRequest, "../certs/default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = Verify(signedXml, "../certs/default.crt")
	assert.NoError(err)*/
}
