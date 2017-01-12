package util

import (
	"io/ioutil"
	"regexp"
	"strings"
)

// LoadCertificate from file system
func LoadCertificate(certPath string) (string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	cert := NormalizeCertificate(string(b))
	return cert, nil
}

// LoadCertificateFromString from string
func LoadCertificateFromString(cert string) string {
	return NormalizeCertificate(cert)
}

func NormalizeCertificate(cert string) string {
	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)
	return cert
}
