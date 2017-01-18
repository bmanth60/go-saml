package saml_test

import (
	"testing"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestApplyLogoutRequest(t *testing.T) {
	settings := GetStandardSettings()
	request := saml.ApplyLogoutRequest(&settings, saml.NewLogoutRequest(), "nameid", "sessionindex")
	request.ID = "id"
	request.IssueInstant = "statictime"
	request.Signature.SignedInfo.SamlsigReference.URI = "#id"

	result, err := request.SignedString(&settings)
	assert.NoError(t, err)

	expected := `
	<LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime">
	    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>G/ibCZGQcZgDO+q/PmNtGGh36Cw=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>xOWhUiCGD6WXCkmdXZCUEAn6ic7Z6Fb+Hdl3csdIuh6/f5pWAzYDyqshofs07SIpAmuy3BwUu4XYBkSxqpVxVNcmb+J5EYwEdEM4g0KgdKi/g6LwRoTXtlcB+ReY9lEXFVzI7zupCtraHq4aHvpygTTAkIeQSU0Mi6+b6wmJWEG1pmSb5YiEOpvpM0jPlHwgVf8DE6mdW8oTrl01L4nuQReW7KYDxiw7gJ5kZmxziqB9kramNKFiw/KxMrI8EwekMfSk2ucmRFTgjx7a2m9SijHj1Q8FxCgmgR8LCd0KivEIv/P5jf6RIVMolOq0tzhk3QB5BLchmYbN4QztT9Ccs1rllTpnkbRrnjNKRO7bGp9Iwz+t8oWuz06vHIrw0VCXz+XKItoQQLhNnmDft6b+yL4ix4E9hmt6B3YIoA99dClqhickNXHBG+u5pWH/ZCfb1eMDIpbEp4LjlQK3iJJGbithcbgGP0EVcdBgA7x6G68zZOWCgpladEeS/SjztE0ZY+PBFR8MqZq9rCAgezxfXe4KPou1g7RbbyUFu8MAWxFl+Q9uHHkx5vNIst7LUbPAXr8vFOUG+Lbz1Fh9kfjc/3KVeVCXGgsJJJlb9aTo7e72dBsEuFd+X7sSQoVGMcb4+rFxPpjHaiaKqhgneV8CiDpyynKdSEa0R+TXDaq9E1I=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <saml:NameID Format="">nameid</saml:NameID>
	    <samlp:SessionIndex>sessionindex</samlp:SessionIndex>
	</LogoutRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(result))
}

func TestCreateLogoutResponse(t *testing.T) {
	response := saml.NewLogoutResponse()
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
	<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="statictime" InResponseTo="">
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
	</samlp:LogoutResponse>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(xmldoc))
}
