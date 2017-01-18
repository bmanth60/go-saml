package saml_test

import (
	"testing"

	"github.com/bmanth60/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestCreateAuthnResponse(t *testing.T) {
	settings := GetStandardSettings()
	response := saml.NewAuthnResponse()
	response.ID = "id"
	response.IssueInstant = "statictime"
	response.Signature.SignedInfo.SamlsigReference.URI = "#id"
	response.Assertion.ID = "id"
	response.Assertion.IssueInstant = "statictime"
	response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = "statictime"
	response.Assertion.Conditions.NotBefore = "statictime"
	response.Assertion.Conditions.NotOnOrAfter = "statictime"

	xmldoc, err := response.SignedString(&settings)
	assert.NoError(t, err)

	expected := `
	<Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="statictime" InResponseTo="">
	    <saml:Issuer/>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>FUpE3zP4PQ0oCh02L7gcwjiKdlw=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>oiUMviOCG1Qo7wWd+P5PiamjuR8JjFO1gIwd92TO9estGnOh99yWw2o6PY6PfH4C8ZD6oXhjAWClGdxe6Uk/VGOEN06sRYcbIpA1yjSX1R23Up/pMsgmyjPrFeKlpOI1uMDKB5Q3hBLM1H1gez5/FJ6tZ4M/e1YNuLX+DVDDDqDT2IF5ut3OzXLJAXn9Vf9hIIeLqRoXdzSPF4WI4NgvDEcvSwHq7HdlnLYrTpGjVgPgz8SabZPNmr2yaEqASQWmIkiZVevppPPn3Fj4CA7BhysBF9JRTPsiA2xaDUDK7OG8R3Jfc91WfS/wBQ/eoDoolJZUzDuDb9fZWiNvHESarRKhKTQ+leaelm/DHnj+zrgUi3Z0B9jPwWAFOLdBJetkEFgtyqRlT4EBmse4cQ1R/DOGI9B1IzPSed+XM7+sPILaQ/W5ywO01l3fkjum4055rBvnx8jvwv++cZ4cK/r3ECM5Yn03rWwldIkK6eiyOgcnRpy8Sgf2RUOjN1/p6wxSK7QOYtQyheQDOn9EAzCTxUh0KMxpxKOUO4ObyQpIvJwGqQzIOHr3Mm05RiG3QUSC/VeFrmqXzjyWPG4nic1v0p0GUPE2p3jWECwZu49SwryW0+f/lq94+8FbeDjRrwG4olctjjV/P4Fd2JOZzWK30vrGFsqfEjcOhe1Y/ZfZmqQ=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate/>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <saml:Assertion ID="id" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="statictime">
	        <saml:Issuer/>
	        <Signature Id="">
	            <SignedInfo>
	                <CanonicalizationMethod Algorithm=""/>
	                <SignatureMethod Algorithm=""/>
	                <SamlsigReference URI="">
	                    <Transforms>
	                        <Transform Algorithm=""/>
	                    </Transforms>
	                    <DigestMethod Algorithm=""/>
	                    <DigestValue/>
	                </SamlsigReference>
	            </SignedInfo>
	            <SignatureValue/>
	            <KeyInfo>
	                <X509Data>
	                    <X509Certificate/>
	                </X509Data>
	            </KeyInfo>
	        </Signature>
	        <saml:Subject>
	            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>
	            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	                <SubjectConfirmationData InResponseTo="" NotOnOrAfter="statictime" Recipient=""/>
	            </saml:SubjectConfirmation>
	        </saml:Subject>
	        <saml:Conditions NotBefore="statictime" NotOnOrAfter="statictime"/>
	        <saml:AttributeStatement/>
	        <saml:AuthnStatement AuthnInstant="">
	            <saml:AuthnContext Comparison="">
	                <saml:AuthnContextClassRef/>
	            </saml:AuthnContext>
	        </saml:AuthnStatement>
	    </saml:Assertion>
	    <samlp:Status>
	        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	    </samlp:Status>
	</Response>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(xmldoc))
}
