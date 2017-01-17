package saml

import "github.com/RobotsAndPencils/go-saml/util"

type SAMLSettings struct {
	SP ServiceProviderSettings
	IDP IdentityProviderSettings

	hasInit bool
}

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	EntityId                    string
	PublicCertPath              string
	PublicCertString            string
	PrivateKeyPath              string
	PrivateKeyString            string
	AssertionConsumerServiceURL string
	SingleLogoutServiceUrl      string
	SignRequest               	bool

	publicCert    string
	privateKey    string
}

type IdentityProviderSettings struct {
	SingleLogoutURL          string
	SingleSignOnURL                   string
	SingleSignOnDescriptorURL         string
	PublicCertPath           string
	PublicCertString         string
	NameIDFormat                string

	publicCert    string
}

func (s *SAMLSettings) Init() (err error) {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	if s.SP.SignRequest {
		s.loadSPCertificate()
	}

	if s.IDP.PublicCertString != "" {
		s.IDP.publicCert = util.LoadCertificateFromString(s.IDP.PublicCertString)
	} else {
		s.IDP.publicCert, err = util.LoadCertificate(s.IDP.PublicCertPath)
		if err != nil {
			panic(err)
		}
	}

	//Set the sp entity id to acs url if not found for
	//backwards compatibility with old configuration
	if s.SP.EntityId == "" && s.SP.AssertionConsumerServiceURL != "" {
		s.SP.EntityId = s.SP.AssertionConsumerServiceURL
	}

	return nil
}

//loadSPCertificate load service provider certificate into settings object
func (s *SAMLSettings) loadSPCertificate() {
	var err error

	if s.SP.PublicCertString != "" {
		s.SP.publicCert = util.LoadCertificateFromString(s.SP.PublicCertString)
	} else {
		s.SP.publicCert, err = util.LoadCertificate(s.SP.PublicCertPath)
		if err != nil {
			panic(err)
		}
	}

	if s.SP.PrivateKeyString != "" {
		s.SP.privateKey = util.LoadCertificateFromString(s.SP.PrivateKeyString)
	} else {
		s.SP.privateKey, err = util.LoadCertificate(s.SP.PrivateKeyPath)
		if err != nil {
			panic(err)
		}
	}
}

func (s *SAMLSettings) SPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return s.SP.publicCert
}

func (s *SAMLSettings) SPPrivateKey() string {
	if !s.hasInit {
		s.Init()
	}
	return s.SP.privateKey
}

func (s *SAMLSettings) IDPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return s.IDP.publicCert
}
