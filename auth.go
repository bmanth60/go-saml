package saml

// This is the main auth class to coordinate typical calls
// for the sp and idp. It performs the following functions:
//
//SP
//Get auth request
//Parse auth response
//Get logout request
//Parse logout response
//
//IDP
//Parse auth request
//Create auth reponse
//Parse logout request
//Create logout response

// TODO
//Load settings

import(
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"

	"encoding/base64"
	"encoding/pem"
)

type SAMLRequest interface {
	ParseCompressedEncodedRequest(b64RequestXML string) error
	ParseEncodedRequest(b64RequestXML string) error
	GetRequestUrl(settings ServiceProviderSettings, state string) (string, error)
}

type SAMLResponse interface {
	ParseCompressedEncodedResponse(b64ResponseXML string) (*Response, error)
	ParseEncodedResponse(b64ResponseXML string) (*Response, error)
}

func GetRequestSignature(data string, key string) (sig string, err error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", ErrPEMFormat
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes) //x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	digest := sha1.Sum([]byte(data))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}
