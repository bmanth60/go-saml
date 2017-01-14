package saml

import (
	"github.com/RobotsAndPencils/go-saml/packager"
)

// Sign creates a signature for an XML document and returns it
func Sign(xml string, privateKeyPath string) (string, error) {
	return packager.Sign(xml, privateKeyPath)
}

func SignWithKey(xml string, pemKey string) (string, error) {
	return packager.SignWithKey(xml, pemKey)
}

// Verify validates the signature of an XML document
func Verify(xml string, publicCertPath string) error {
	return packager.Verify(xml, publicCertPath)
}

func VerifyWithCert(xml string, certPem string) error {
	return packager.VerifyWithCert(xml, certPem)
}
