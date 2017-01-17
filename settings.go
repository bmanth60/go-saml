package saml

import "github.com/RobotsAndPencils/go-saml/util"

//Settings to configure saml properties for
//one idp and/or one sp.
//If you need to configure multipe IDPs for an SP
//then configure multiple instances of this object
type Settings struct {
	SP  ServiceProviderSettings
	IDP IdentityProviderSettings

	hasInit bool
}

//ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
//Expect only one IDP per SP in this configuration.
type ServiceProviderSettings struct {
	EntityID                    string
	PublicCertPath              string
	PublicCertString            string
	PrivateKeyPath              string
	PrivateKeyString            string
	AssertionConsumerServiceURL string
	SingleLogoutServiceURL      string
	SignRequest                 bool

	publicCert string
	privateKey string
}

//IdentityProviderSettings to configure idp specific settings
type IdentityProviderSettings struct {
	SingleLogoutURL           string
	SingleSignOnURL           string
	SingleSignOnDescriptorURL string
	PublicCertPath            string
	PublicCertString          string
	NameIDFormat              string

	publicCert string
}

//Init settings and load configuration files as needed
//This will panic on error as SP/IDP fails to load
func (s *Settings) Init() (err error) {
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
	if s.SP.EntityID == "" && s.SP.AssertionConsumerServiceURL != "" {
		s.SP.EntityID = s.SP.AssertionConsumerServiceURL
	}

	return nil
}

//loadSPCertificate load service provider certificate into settings object
func (s *Settings) loadSPCertificate() {
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

//SPPublicCert get loaded sp public certificate
func (s *Settings) SPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return s.SP.publicCert
}

//SPPrivateKey get loaded sp private key
func (s *Settings) SPPrivateKey() string {
	if !s.hasInit {
		s.Init()
	}
	return s.SP.privateKey
}

//IDPPublicCert get loaded idp public certificate
func (s *Settings) IDPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return s.IDP.publicCert
}
