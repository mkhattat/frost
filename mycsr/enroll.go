package mycsr

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"net/url"

	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/mkhattat/frost"
	"github.com/pkg/errors"
)

// ClientConfig is the fabric-ca client's config
type ClientConfig struct {
	URL        string `def:"http://localhost:7054" opt:"u" help:"URL of fabric-ca-server"`
	MSPDir     string `def:"msp" opt:"M" help:"Membership Service Provider directory"`
	TLS        tls.ClientTLSConfig
	Enrollment api.EnrollmentRequest
	CSR        api.CSRInfo
	ID         api.RegistrationRequest
	Revoke     api.RevocationRequest
	CAInfo     api.GetCAInfoRequest
	CAName     string               `help:"Name of CA"`
	CSP        *factory.FactoryOpts `mapstructure:"bccsp" hide:"true"`
	Debug      bool                 `opt:"d" help:"Enable debug level logging" hide:"true"`
	LogLevel   string               `help:"Set logging level (info, warning, debug, error, fatal, critical)"`
	Idemix     api.Idemix
	PK         crypto.PublicKey
	KeyShares  []*secretsharing.KeyShare
}

// Enroll a client given the server's URL and the client's home directory.
// The URL may be of the form: http://user:pass@host:port where user and pass
// are the enrollment ID and secret, respectively.
func (c *ClientConfig) Enroll(rawurl, home string) (*EnrollmentResponse, error) {
	purl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if purl.User != nil {
		name := purl.User.Username()
		secret, _ := purl.User.Password()
		c.Enrollment.Name = name
		c.Enrollment.Secret = secret
		purl.User = nil
	}
	if c.Enrollment.Name == "" {
		expecting := fmt.Sprintf(
			"%s://<enrollmentID>:<secret>@%s",
			purl.Scheme, purl.Host)
		return nil, errors.Errorf(
			"The URL of the fabric CA server is missing the enrollment ID and secret;"+
				" found '%s' but expecting '%s'", rawurl, expecting)
	}
	c.Enrollment.CAName = c.CAName
	c.URL = purl.String()
	c.TLS.Enabled = purl.Scheme == "https"
	c.Enrollment.CSR = &c.CSR
	client := &Client{HomeDir: home, Config: c}
	return client.Enroll(&c.Enrollment)
}

func (c *ClientConfig) FrostSign(message []byte) []byte {
	conf := frost.Ed25519.Configuration()
	groupPublicKey := conf.Ciphersuite.Group.NewElement()
	groupPublicKey.UnmarshalBinary(c.PK.(ed25519.PublicKey))
	return frost.Sign(conf, c.KeyShares, groupPublicKey, message)
}
