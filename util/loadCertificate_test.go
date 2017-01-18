package util_test

import (
	"strings"
	"testing"

	"github.com/RobotsAndPencils/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestLoadCertificateFile(t *testing.T) {
	cert, err := util.LoadCertificate("/go/src/github.com/RobotsAndPencils/go-saml/certs/default.crt")
	assert.NoError(t, err)

	//All newlines should have been removed
	assert.False(t, strings.Contains(cert, "\n"))
}
