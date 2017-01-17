package saml

import (
	"testing"

	"github.com/RobotsAndPencils/go-saml/packager"
	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	assert := assert.New(t)
	settings := Settings{
		SP: ServiceProviderSettings{
			PublicCertPath:              "./certs/default.crt",
			PrivateKeyPath:              "./certs/default.key",
			AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
			SignRequest:                 true,
		},
		IDP: IdentityProviderSettings{
			SingleSignOnURL:           "http://www.onelogin.net",
			SingleSignOnDescriptorURL: "http://www.onelogin.net",
			PublicCertPath:            "./certs/default.crt",
		},
	}
	err := settings.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := GetAuthnRequest(settings)
	signedXML, err := authnRequest.SignedString(settings.SP.PrivateKeyPath)
	assert.NoError(err)
	assert.NotEmpty(signedXML)

	err = packager.Verify(signedXML, settings.SP.PublicCertPath)
	assert.NoError(err)
}

func TestGetUnsignedRequest(t *testing.T) {
	assert := assert.New(t)
	settings := Settings{
		SP: ServiceProviderSettings{
			AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
			SignRequest:                 false,
		},
		IDP: IdentityProviderSettings{
			SingleSignOnURL:           "http://www.onelogin.net",
			SingleSignOnDescriptorURL: "http://www.onelogin.net",
			PublicCertPath:            "./certs/default.crt",
		},
	}
	err := settings.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := GetAuthnRequest(settings)
	assert.NoError(err)
	assert.NotEmpty(authnRequest)
}
