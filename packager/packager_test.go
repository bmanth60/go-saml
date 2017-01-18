package packager_test

import (
	"encoding/xml"
	"regexp"
	"strings"
	"testing"

	"github.com/RobotsAndPencils/go-saml/packager"
	"github.com/stretchr/testify/assert"
)

type TestData struct {
	XMLName      xml.Name
	SAMLP        string              `xml:"xmlns:samlp,attr"`
	SAML         string              `xml:"xmlns:saml,attr"`
	SAMLSIG      string              `xml:"xmlns:samlsig,attr,omitempty"`
	ID           string              `xml:"ID,attr"`
	Version      string              `xml:"Version,attr"`
	Destination  string              `xml:"Destination,attr"`
	IssueInstant string              `xml:"IssueInstant,attr"`
	Signature    *packager.Signature `xml:"Signature,omitempty"`
}

//SquashWhitespace Squashes multiple whitespaces into single space
func SquashWhitespace(data string) string {
	regSquashWhiteSpace := regexp.MustCompile(`[\s\p{Zs}]{1,}`)
	return regSquashWhiteSpace.ReplaceAllString(strings.TrimSpace(data), " ")
}

//GetTestData get test xml data object
func GetTestData() *TestData {
	return &TestData{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
		ID:           "id",
		Version:      "2.0",
		IssueInstant: "2017-01-17T19:05:24.15287472Z",
		Signature:    packager.GetSignatureEntity("id"),
	}
}

func TestSignedString(t *testing.T) {
	xmlreq := GetTestData()
	signed, err := packager.SignedString(xmlreq, "/go/src/github.com/RobotsAndPencils/go-saml/certs/default.key")
	assert.NoError(t, err)

	expected := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="2017-01-17T19:05:24.15287472Z">
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>TM7GuhDFajQAb8paaC07ShmMyf0=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>FayUnGOPjnvlV1mm5JftzuKNyf/L05E1LZAxsRGxydu0r022Wz4BNBGnn8x8wztMaXZPPpSJpFVdko7jgJdhCsl1IhUTUAKfJZZfFZ8cDoqALg3lz2V0REN247U/+zGO7oLTNhzSWM2MynQLZjmjxShwNKI8PGy0a8EOZBSemdQklZvVTga3/i/7z+h/VVS53CL8YVjlFlbxlLlQXkG1EVyt9Ve6syLwFfQL7P39hd2z05iI8Tpgizi90/eGCd20y6c9btohkXWSTGYq2lFEszYJneHOb2OKO5dE8n4Up4OtNlctL15HmE0gWbqfNd2ePu5US/8Ow4raH8JQWtH0KEDog4yiE/LVl/AxbdGgx+opGGLr5v/IR8+yl+mNZJtj+ECaY58J5FrY60gxZvEf9HHY23CS91Q4UxLNYP52gaI08ChhrYbEp23O2/0ShepAkQFtlDEqJimZ4ZvI2kTRCMgyqd8uniQEld3WHSStnxllc08RNKq86QXW192E/cSWVwnDyPV/vk/A1wz5pQs9q8u8hUPNEm4n7tJcfRqwcZfdauVymoKWttMGiUKeN7HhbGv+bgr00ZDqLTamnHw0QnMV1BC+vZR765E3O+5l0ak+XBJ0wMdTo8QpZ3HgQ/jYhiTSAqn6vzMyKNwwsPjfwejrl+oW1iU/J2fWF2gPRxk=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate/>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	</samlp:AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}
