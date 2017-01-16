package packager

import (
	"encoding/base64"
	"encoding/xml"

	"github.com/RobotsAndPencils/go-saml/util"
)

func String(data interface{}) (string, error) {
	b, err := xml.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func SignedString(data interface{}, privateKeyPath string) (string, error) {
	str, err := String(data)
	if err != nil {
		return "", err
	}

	return Sign(str, privateKeyPath)
}

func EncodedSignedString(data interface{}, privateKeyPath string) (string, error) {
	signed, err := SignedString(data, privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

//CompressedEncodedSignedStringFromKey sign string with sp key, compress, then base64 encode
func CompressedEncodedSignedStringFromKey(data interface{}, key string) (string, error) {
	str, err := String(data)
	if err != nil {
		return "", err
	}

	signed, err := SignWithKey(str, key)
	if err != nil {
		return "", err
	}

	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

func CompressedEncodedSignedString(data interface{}, privateKeyPath string) (string, error) {
	signed, err := SignedString(data, privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

func EncodedString(data interface{}) (string, error) {
	saml, err := String(data)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(saml))
	return b64XML, nil
}

func CompressedEncodedString(data interface{}) (string, error) {
	saml, err := String(data)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(saml))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

func DecodeAndInflateString(data string) ([]byte, error) {
	compressedXML, err := DecodeString(data)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)
	return bXML, nil
}

func DecodeString(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
