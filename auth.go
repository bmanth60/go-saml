package saml

// [WIP] This is the main auth class to coordinate typical calls
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

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"

	"encoding/base64"
	"encoding/pem"
)

//GetAuthnRequestURL as SP, generate authentication request url to perform sso
func GetAuthnRequestURL() {
	//Check settings for data
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)
	u.RawQuery = q.Encode()
	return u.String(), nil

	r := GetAuthnRequest()
	r.NameIDPolicy.Format = settings.IDP.NameIDFormat

	// Sign the request
	b64XML, err := packager.CompressedEncodedSignedStringFromKey(r, settings.SP.privateKey)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(settings.IDP.SingleSignOnURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)
	q.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

	//Build signature string. Digest must be in this order.
	sigstr := "SAMLRequest=" + url.QueryEscape(q.Get("SAMLRequest")) +
		"&RelayState=" + url.QueryEscape(q.Get("RelayState")) +
		"&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))

	sig, err := GetRequestSignature(sigstr, settings.SP.privateKey)
	if err != nil {
		return "", err
	}

	q.Set("Signature", sig)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

//ParseAuthnRequest as IDP, parse incoming authentication request
func ParseAuthnRequest() {
	bXML, err := packager.DecodeAndInflateString(b64RequestXML)
	bytesXML, err := packager.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}

	authnRequest := new(AuthnRequest)
	err = xml.Unmarshal(bytesXML, &authnRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnRequest.originalString = string(bytesXML)
	return authnRequest, nil
}

//ParseAuthnResponse as SP, parse incoming authentication response
func ParseAuthnResponse() {

}

//GetLogoutUrl as SP, generate logout request url to perform slo
func GetLogoutRequestUrl(settings ServiceProviderSettings, state string, nameID string, sessionIndex string) (string, error) {
	r := GetLogoutRequest(settings, nameID, sessionIndex)

	// Sign the request
	b64XML, err := packager.CompressedEncodedSignedStringFromKey(r, settings.SP.privateKey)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(settings.IDP.SingleLogoutURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)
	q.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

	//Build signature string. Digest must be in this order.
	sigstr := "SAMLRequest=" + url.QueryEscape(q.Get("SAMLRequest")) +
		"&RelayState=" + url.QueryEscape(q.Get("RelayState")) +
		"&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))

	sig, err := GetRequestSignature(sigstr, settings.SP.privateKey)
	if err != nil {
		return "", err
	}

	q.Set("Signature", sig)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

//ParseLogoutRequest as IDP, parse incoming logout request
func ParseLogoutRequest() {

}

//ParseLogoutResponse as SP, parse incoming logout response
func ParseLogoutResponse() {

}

//GetRequestSignature for the request url
func GetRequestSignature(data string, key string) (string, error) {
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
