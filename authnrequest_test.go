package saml_test

import (
	"testing"

	saml "github.com/RobotsAndPencils/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	settings := GetStandardSettings()
	err := settings.Init()
	assert.NoError(t, err)

	// Construct an AuthnRequest
	request := saml.ApplyAuthnRequest(settings, saml.NewAuthnRequest())
	request.ID = "id"
	request.IssueInstant = "statictime"
	request.Signature.SignedInfo.SamlsigReference.URI = "#id"

	signedXML, err := request.SignedString(settings.SP.PrivateKeyPath)
	assert.NoError(t, err)

	expected := `
	<AuthnRequest
	    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	    xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://localhost:8000/auth/saml/name" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
	    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://www.onelogin.net</saml:Issuer>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo
	            xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>lwDKdChI5EobZmvRaXHmlRPMk4w=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>T7rWejVzRDSn0nYtkM6bseUHOQRWs8KWlE0ssa/Wz6fjcljzujLVn97Kw0UtBfrb4q/do16NX41RY2ciWTkxNOCWdo9n4jdTDnuzsJ3ReMnYPHDYAuz3ABHtyuUsjtE2Lck6n8K9saKlVWPfb1lc4zFSQ2qAZfPfdukrBgj8Rj2MI8w79m0ILpmXMy5gCLRPeSDXy/3dPCrdaJqU4hbnfvT8OTYX+tuuLNDP6wgtwPW++IWGf30It24eoZ+CguqQV7Biem8DRJp1Ir1BrYpCocEhYGTYIpSyoeEsIgOGHK7UupFZi4EK7PNjxRd/frXmr2PxZeat+9MEmsgSb9jf8dKNgtOPTLilTNlmTMwgseNl9ag2xjctdQPnrEFZZu2Y0LuHcifXyxj1c8lIBnu4OPKZZ8eeFa08q65SKB6j4HhZhiPkvmXVDJ+rfUvpJWH4EoX6TS4/MKWvXT0tOBMens9kuTc3F29UMrmxbsx871YvZz0HpHRA8XSj/ZCm0t3t6AbZufzn92R67jsiseBfaRrqc4g82ohJ70TPciUTMP88+QzTpE0gYKSV1ewJOHcCCfEuuOrOTsGMOopVsj3xUG+BXowffTBn44kaWhR8LDfuVf67+L7CqjZGwBk7s3dEGy6T67itO2FECEvha975q3o1PlL/+FS6wtxRxMyaTz8=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <samlp:NameIDPolicy AllowCreate="true" Format=""/>
	    <samlp:RequestedAuthnContext
	        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
	        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
	    </samlp:RequestedAuthnContext>
	</AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signedXML))
}

func TestGetUnsignedRequest(t *testing.T) {
	settings := GetStandardSettings()
	settings.SP.SignRequest = false

	err := settings.Init()
	assert.NoError(t, err)

	// Construct an AuthnRequest
	request := saml.ApplyAuthnRequest(settings, saml.NewAuthnRequest())
	request.ID = "id"
	request.IssueInstant = "statictime"

	reqxml, err := request.String()
	assert.NoError(t, err)

	expected := `
	<AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://localhost:8000/auth/saml/name" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
	    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://www.onelogin.net</saml:Issuer>
	    <samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy>
	    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
	        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
	    </samlp:RequestedAuthnContext>
	</AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(reqxml))
}
