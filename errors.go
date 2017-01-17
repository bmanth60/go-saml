package saml

import "errors"

var (
	//ErrPEMFormat error with pem format
	ErrPEMFormat = errors.New("Certificate not valid pem format")
)
