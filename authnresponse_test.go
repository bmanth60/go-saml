package saml_test

import (
	"testing"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestCreateAuthnResponse(t *testing.T) {
	response := saml.NewSignedResponse()
	response.ID = "id"
	response.IssueInstant = "statictime"
	response.Signature.SignedInfo.SamlsigReference.URI = "#id"
	response.Assertion.ID = "id"
	response.Assertion.IssueInstant = "statictime"
	response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = "statictime"
	response.Assertion.Conditions.NotBefore = "statictime"
	response.Assertion.Conditions.NotOnOrAfter = "statictime"

	xmldoc, err := response.String()
	assert.NoError(t, err)

	expected := `
	<Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="statictime" InResponseTo="">
	    <saml:Issuer></saml:Issuer>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo>
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></samlsig:CanonicalizationMethod>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></samlsig:SignatureMethod>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></samlsig:Transform>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></samlsig:DigestMethod>
	                <samlsig:DigestValue></samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue></samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate></samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <saml:Assertion ID="id" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="statictime">
	        <saml:Issuer></saml:Issuer>
	        <Signature Id="">
	            <SignedInfo>
	                <CanonicalizationMethod Algorithm=""></CanonicalizationMethod>
	                <SignatureMethod Algorithm=""></SignatureMethod>
	                <SamlsigReference URI="">
	                    <Transforms>
	                        <Transform Algorithm=""></Transform>
	                    </Transforms>
	                    <DigestMethod Algorithm=""></DigestMethod>
	                    <DigestValue></DigestValue>
	                </SamlsigReference>
	            </SignedInfo>
	            <SignatureValue></SignatureValue>
	            <KeyInfo>
	                <X509Data>
	                    <X509Certificate></X509Certificate>
	                </X509Data>
	            </KeyInfo>
	        </Signature>
	        <saml:Subject>
	            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"></saml:NameID>
	            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	                <SubjectConfirmationData InResponseTo="" NotOnOrAfter="statictime" Recipient=""></SubjectConfirmationData>
	            </saml:SubjectConfirmation>
	        </saml:Subject>
	        <saml:Conditions NotBefore="statictime" NotOnOrAfter="statictime"></saml:Conditions>
	        <saml:AttributeStatement></saml:AttributeStatement>
	        <AuthnStatement AuthnInstant="">
	            <AuthnContext Comparison="">
	                <AuthnContextClassRef></AuthnContextClassRef>
	            </AuthnContext>
	        </AuthnStatement>
	    </saml:Assertion>
	    <samlp:Status>
	        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
	    </samlp:Status>
	</Response>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(xmldoc))
}
