package saml_test

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/RobotsAndPencils/go-saml/packager"
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
			AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
			SignRequest:                 true,
		},
		IDP: saml.IdentityProviderSettings{
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

	request := info.Query().Get("SAMLRequest")
	assert.Equal(t, "www.onelogin.net", info.Host)
	assert.Equal(t, "relay", info.Query().Get("RelayState"))
	assert.NotEmpty(t, request)
	assert.NotEmpty(t, info.Query().Get("SigAlg"))
	assert.NotEmpty(t, info.Query().Get("Signature"))

	raw, err := packager.DecodeAndInflateString(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, raw)
}

/*
ParseAuthnRequest
ParseAuthnResponse
GetLogoutRequestURL
ParseLogoutRequest
ParseLogoutResponse
*/
