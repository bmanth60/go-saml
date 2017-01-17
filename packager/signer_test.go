package packager

import (
	"encoding/xml"
	"testing"

	"github.com/RobotsAndPencils/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	assert := assert.New(t)
	cert, err := util.LoadCertificate("../certs/default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	authRequest := NewAuthnRequest()
	authRequest.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err := xml.MarshalIndent(authRequest, "", "    ")
	assert.NoError(err)
	xmlAuthnRequest := string(b)

	signedXml, err := Sign(xmlAuthnRequest, "../certs/default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = Verify(signedXml, "../certs/default.crt")
	assert.NoError(err)
}

func TestResponse(t *testing.T) {
	assert := assert.New(t)
	cert, err := util.LoadCertificate("../certs/default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	response := NewSignedResponse()
	response.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err := xml.MarshalIndent(response, "", "    ")
	assert.NoError(err)
	xmlResponse := string(b)

	signedXml, err := Sign(xmlResponse, "../certs/default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = Verify(signedXml, "../certs/default.crt")
	assert.NoError(err)
}
