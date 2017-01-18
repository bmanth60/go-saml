package saml_test

import (
	"testing"

	"github.com/RobotsAndPencils/go-saml"
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
	                <samlsig:DigestValue>sIJnDojC5lMetWScbWoXONSIeJ4=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>uqpKC2+1kgsNMYnKtTtntilK6DlQV6rvERnOPevk2PpNl45vVIwGexibIX1uwn44IdWi0sW4opHoFvWwgBv5EPp0NjBhqg0D3ReNbxvDeECoev2PLXLFkxEHESMI/83rBFtu5tZ3qG6HNW3fK2y+LoZvYJjdrR0GXXeq3IrqQqOycmTZZ639qbjtask2DniY1vNMueliqd3gt3jkCGjtQjDK2lOFrE4qN/JuO7rDGUczV5sTbL3A0uIOSsFLUseHgDgG+nd8zFwmLW8SdJzV6wAPtiOfDp6xY82lbWoZjJ8TZ7tYwtmIKw08LnkQsCv2nWuItH4arBo0SXUbZVVLll8sE6xYwinCbJ/F7RQCxnVzQDq0faDkFJBeuIWzDf4ka9fCOUUUVsyB+FFUkChVpHagO8xYOt7mBzkHaGFoxEChF30e4V36pgM6DQlXUuxhvm2TVYHsIoBoDMnJiB2uXwyJ9BQIUG01ZfwfjaTSmox1aSp3U0HtdIsPEJmadaY+SfiqyQX0jHrJa6B5DCQMRrd9ovht2aaiVLw4PF6hIsI7ZfpTH6F/8dL3Skbphe1RhljcEYPl2nkRNHTB6d3zaOby+2/0hbhqYwXe8N6Yc9mx3nOWDH0VFP5Iw1INugJtXgkVEOXxdwICc4oMOJ4/TcEYXxKxhl1K5OPSOwoGyEI=</samlsig:SignatureValue>
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
	        <AuthnStatement AuthnInstant="">
	            <AuthnContext Comparison="">
	                <AuthnContextClassRef/>
	            </AuthnContext>
	        </AuthnStatement>
	    </saml:Assertion>
	    <samlp:Status>
	        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	    </samlp:Status>
	</Response>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(xmldoc))
}
