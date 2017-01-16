package saml

import "github.com/RobotsAndPencils/go-saml/util"

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	EntityId                    string
	PublicCertPath              string
	PublicCertString            string
	PrivateKeyPath              string
	PrivateKeyString            string
	IDPSingleLogoutURL          string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCertPath           string
	IDPPublicCertString         string
	AssertionConsumerServiceURL string
	SingleLogoutServiceUrl      string
	NameIDFormat          string
	SPSignRequest               bool

	hasInit       bool
	publicCert    string
	privateKey    string
	iDPPublicCert string
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) Init() (err error) {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	if s.SPSignRequest {
		s.loadSPCertificate()
	}

	if s.IDPPublicCertString != "" {
		s.iDPPublicCert = util.LoadCertificateFromString(s.IDPPublicCertString)
	} else {
		s.iDPPublicCert, err = util.LoadCertificate(s.IDPPublicCertPath)
		if err != nil {
			panic(err)
		}
	}

	//Set the sp entity id to acs url if not found for
	//backwards compatibility with old configuration
	if s.EntityId == "" && s.AssertionConsumerServiceURL != "" {
		s.EntityId = s.AssertionConsumerServiceURL
	}

	return nil
}

//loadSPCertificate load service provider certificate into settings object
func (s *ServiceProviderSettings) loadSPCertificate() {
	var err error

	if s.PublicCertString != "" {
		s.publicCert = util.LoadCertificateFromString(s.PublicCertString)
	} else {
		s.publicCert, err = util.LoadCertificate(s.PublicCertPath)
		if err != nil {
			panic(err)
		}
	}

	if s.PrivateKeyString != "" {
		s.privateKey = util.LoadCertificateFromString(s.PrivateKeyString)
	} else {
		s.privateKey, err = util.LoadCertificate(s.PrivateKeyPath)
		if err != nil {
			panic(err)
		}
	}
}

func (s *ServiceProviderSettings) PublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return s.publicCert
}

func (s *ServiceProviderSettings) PrivateKey() string {
	if !s.hasInit {
		s.Init()
	}
	return s.privateKey
}

func (s *ServiceProviderSettings) IDPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return s.iDPPublicCert
}
