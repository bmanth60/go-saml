package saml_test

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/stretchr/testify/assert"
)

//SquashWhitespace Squashes multiple whitespaces into single space
func SquashWhitespace(data string) string {
	regSquashWhiteSpace := regexp.MustCompile(`[\s\p{Zs}]{1,}`)
	return regSquashWhiteSpace.ReplaceAllString(strings.TrimSpace(data), " ")
}

//GetStandardSettings get typical saml settings
func GetStandardSettings() saml.Settings {
	return saml.Settings{
		SP: saml.ServiceProviderSettings{
			PublicCertPath:              "/go/src/github.com/RobotsAndPencils/go-saml/certs/default.crt",
			PrivateKeyPath:              "/go/src/github.com/RobotsAndPencils/go-saml/certs/default.key",
			SingleLogoutServiceURL:      "http://localhost:8000/auth/saml/sls",
			AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/acs",
			SignRequest:                 true,
		},
		IDP: saml.IdentityProviderSettings{
			SingleLogoutURL:           "http://www.onelogin.net",
			SingleSignOnURL:           "http://www.onelogin.net",
			SingleSignOnDescriptorURL: "http://www.onelogin.net",
			PublicCertPath:            "/go/src/github.com/RobotsAndPencils/go-saml/certs/default.crt",
		},
		Compress: saml.CompressionSettings{
			Request:  true,
			Response: true,
		},
	}
}

func TestGetAuthnRequestURL(t *testing.T) {
	settings := GetStandardSettings()
	authlink, err := saml.GetAuthnRequestURL(settings, "relay")
	assert.NoError(t, err)

	info, err := url.Parse(authlink)
	assert.NoError(t, err)

	encRequest := info.Query().Get("SAMLRequest")
	assert.Equal(t, settings.IDP.SingleSignOnURL, info.Scheme+"://"+info.Host)
	assert.Equal(t, "relay", info.Query().Get("RelayState"))
	assert.NotEmpty(t, encRequest)
	assert.NotEmpty(t, info.Query().Get("SigAlg"))
	assert.NotEmpty(t, info.Query().Get("Signature"))

	request, err := saml.ParseAuthnRequest(settings, encRequest)
	assert.NoError(t, err)
	assert.NotEmpty(t, request)
}

func TestParseAuthnRequest(t *testing.T) {
	settings := GetStandardSettings()
	request := `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`

	result, err := saml.ParseAuthnRequest(settings, request)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestParseAuthnResponse(t *testing.T) {
}

func TestGetLogoutRequestURL(t *testing.T) {
	settings := GetStandardSettings()
	logoutlink, err := saml.GetLogoutRequestURL(settings, "relay", "nameid", "sessionindex")
	assert.NoError(t, err)

	info, err := url.Parse(logoutlink)
	assert.NoError(t, err)

	encRequest := info.Query().Get("SAMLRequest")
	assert.Equal(t, settings.IDP.SingleLogoutURL, info.Scheme+"://"+info.Host)
	assert.Equal(t, "relay", info.Query().Get("RelayState"))
	assert.NotEmpty(t, encRequest)
	assert.NotEmpty(t, info.Query().Get("SigAlg"))
	assert.NotEmpty(t, info.Query().Get("Signature"))

	request, err := saml.ParseLogoutRequest(settings, encRequest)
	assert.NoError(t, err)
	assert.NotEmpty(t, request)

	assert.Equal(t, "nameid", request.NameID.Value)
	assert.Equal(t, "sessionindex", request.SessionIndex.Value)
}

func TestParseLogoutRequest(t *testing.T) {
	settings := GetStandardSettings()
	request := `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`

	result, err := saml.ParseAuthnRequest(settings, request)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestParseLogoutResponse(t *testing.T) {

}
