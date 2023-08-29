package mycsr

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/client/credential"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	idemix2 "github.com/hyperledger/fabric-ca/lib/common/idemix"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

// Identity is fabric-ca's implementation of an identity
type Identity struct {
	name   string
	client *Client
	creds  []credential.Credential
}

// Client is the fabric-ca client object
type Client struct {
	// The client's home directory
	HomeDir string `json:"homeDir,omitempty"`
	// The client's configuration
	Config *ClientConfig
	// Denotes if the client object is already initialized
	initialized bool
	// File and directory paths
	keyFile, certFile, idemixCredFile, idemixCredsDir, ipkFile, caCertsDir string
	// The crypto service provider (BCCSP)
	csp bccsp.BCCSP
	// HTTP client associated with this Fabric CA client
	httpClient *http.Client
	// Public key of Idemix issuer
	issuerPublicKey *idemix.IssuerPublicKey
	idemix          *idemix.Idemix
	curve           *math.Curve
	curveID         cidemix.CurveID
}

// GetCAInfoResponse is the response from the GetCAInfo call
type GetCAInfoResponse struct {
	// CAName is the name of the CA
	CAName string
	// CAChain is the PEM-encoded bytes of the fabric-ca-server's CA chain.
	// The 1st element of the chain is the root CA cert
	CAChain []byte
	// Idemix issuer public key of the CA
	IssuerPublicKey []byte
	// Idemix issuer revocation public key of the CA
	IssuerRevocationPublicKey []byte
	// Version of the server
	Version string
}

// EnrollmentResponse is the response from Client.Enroll and Identity.Reenroll
type EnrollmentResponse struct {
	Identity *Identity
	CAInfo   GetCAInfoResponse
}

// KeyRequest encapsulates size and algorithm for the key to be generated.
// If ReuseKey is set, reenrollment requests will reuse the existing private
// key.
type KeyRequest struct {
	Algo     string `json:"algo" yaml:"algo" help:"Specify key algorithm"`
	Size     int    `json:"size" yaml:"size" help:"Specify key size"`
	ReuseKey bool   `json:"reusekey" yaml:"reusekey" help:"Reuse existing key during reenrollment"`
}

// Enroll enrolls a new identity
// @param req The enrollment request
func (c *Client) Enroll(req *api.EnrollmentRequest) (*EnrollmentResponse, error) {
	log.Info("Enrolling %+v", req)

	err := c.Init()
	if err != nil {
		return nil, err
	}

	return c.handleX509Enroll(req)
}

// Init initializes the client
func (c *Client) Init() error {
	if !c.initialized {
		cfg := c.Config
		log.Debugf("Initializing client with config: %+v", cfg)
		if cfg.MSPDir == "" {
			cfg.MSPDir = "msp"
		}
		mspDir, err := util.MakeFileAbs(cfg.MSPDir, c.HomeDir)
		if err != nil {
			return err
		}
		cfg.MSPDir = mspDir
		// Key directory and file
		keyDir := path.Join(mspDir, "keystore")
		err = os.MkdirAll(keyDir, 0o700)
		if err != nil {
			return errors.Wrap(err, "Failed to create keystore directory")
		}
		c.keyFile = path.Join(keyDir, "key.pem")

		// Cert directory and file
		certDir := path.Join(mspDir, "signcerts")
		err = os.MkdirAll(certDir, 0o755)
		if err != nil {
			return errors.Wrap(err, "Failed to create signcerts directory")
		}
		c.certFile = path.Join(certDir, "cert.pem")

		// CA certs directory
		c.caCertsDir = path.Join(mspDir, "cacerts")
		err = os.MkdirAll(c.caCertsDir, 0o755)
		if err != nil {
			return errors.Wrap(err, "Failed to create cacerts directory")
		}

		// CA's Idemix public key
		c.ipkFile = filepath.Join(mspDir, "IssuerPublicKey")

		// Idemix credentials directory
		c.idemixCredsDir = path.Join(mspDir, "user")
		err = os.MkdirAll(c.idemixCredsDir, 0o755)
		if err != nil {
			return errors.Wrap(err, "Failed to create Idemix credentials directory 'user'")
		}
		c.idemixCredFile = path.Join(c.idemixCredsDir, "SignerConfig")

		// Initialize BCCSP (the crypto layer)
		c.csp, err = util.InitBCCSP(&cfg.CSP, mspDir, c.HomeDir)
		if err != nil {
			return err
		}
		// Create http.Client object and associate it with this client
		err = c.initHTTPClient()
		if err != nil {
			return err
		}

		curveID, err := curveIDFromConfig(cfg.Idemix.Curve)
		if err != nil {
			return err
		}
		c.curveID = curveID
		c.curve = cidemix.CurveByID(curveID)
		c.idemix = cidemix.InstanceForCurve(curveID)

		// Successfully initialized the client
		c.initialized = true
	}
	return nil
}

func (c *Client) handleX509Enroll(req *api.EnrollmentRequest) (*EnrollmentResponse, error) {
	// Generate the CSR
	log.Info(">>>>handleX509Enroll")
	csrPEM, key, err := c.GenCSR(req.CSR, req.Name)
	fmt.Printf("csrPEM: %+v\nkey: %+v\n", csrPEM, key)
	if err != nil {
		return nil, errors.WithMessage(err, "Failure generating CSR")
	}

	// reqNet := &api.EnrollmentRequestNet{
	// 	CAName:   req.CAName,
	// 	AttrReqs: req.AttrReqs,
	// }
	//
	// if req.CSR != nil {
	// 	reqNet.SignRequest.Hosts = req.CSR.Hosts
	// }
	// reqNet.SignRequest.Request = string(csrPEM)
	// reqNet.SignRequest.Profile = req.Profile
	// reqNet.SignRequest.Label = req.Label
	//
	// body, err := util.Marshal(reqNet, "SignRequest")
	// if err != nil {
	// 	return nil, err
	// }
	//
	// // Send the CSR to the fabric-ca server with basic auth header
	// post, err := c.newPost("enroll", body)
	// if err != nil {
	// 	return nil, err
	// }
	// post.SetBasicAuth(req.Name, req.Secret)
	// var result api.EnrollmentResponseNet
	// err = c.SendReq(post, &result)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// // Create the enrollment response
	// return c.newEnrollmentResponse(&result, req.Name, key)
	return nil, nil
}

func (c *Client) initHTTPClient() error {
	tr := new(http.Transport)
	if c.Config.TLS.Enabled {
		log.Info("TLS Enabled")

		err := tls.AbsTLSClient(&c.Config.TLS, c.HomeDir)
		if err != nil {
			return err
		}

		tlsConfig, err2 := tls.GetClientTLSConfig(&c.Config.TLS, c.csp)
		if err2 != nil {
			return fmt.Errorf("Failed to get client TLS config: %s", err2)
		}
		// set the default ciphers
		tlsConfig.CipherSuites = tls.DefaultCipherSuites
		tr.TLSClientConfig = tlsConfig
	}
	c.httpClient = &http.Client{Transport: tr}
	return nil
}

func curveIDFromConfig(idemixCurveName string) (idemix2.CurveID, error) {
	if idemixCurveName == "" {
		idemixCurveName = idemix2.DefaultIdemixCurve
		log.Debugf("CurveID for Idemix not specified, defaulting to %s", idemixCurveName)
		return idemix2.Curves.ByName(idemixCurveName), nil
	}

	curveID := idemix2.Curves.ByName(idemixCurveName)
	if curveID == idemix2.Undefined {
		return 0, errors.Errorf("CurveID '%s' doesn't exist, expecting one of %s", idemixCurveName, idemix2.Curves.Names())
	}
	log.Debugf("Using curve %s for Idemix", idemixCurveName)
	return curveID, nil
}

// GenCSR generates a CSR (Certificate Signing Request)
func (c *Client) GenCSR(req *api.CSRInfo, id string) ([]byte, bccsp.Key, error) {
	log.Info("GenCSR %+v %+v", req, req.KeyRequest)

	err := c.Init()
	if err != nil {
		return nil, nil, err
	}

	cr := c.newCertificateRequest(req, id)

	fmt.Printf(">>>>>>CR %+v\n", cr)
	cspSigner, key, err := c.generateCSPSigner(cr, nil)
	if err != nil {
		log.Info(">>>>cspSigner failed: ", err)
		return nil, nil, err
	}

	csrPEM, err := csr.Generate(cspSigner, cr)
	if err != nil {
		log.Debugf("failed generating CSR: %s", err)
		return nil, nil, err
	}

	return csrPEM, key, nil
}

// newCertificateRequest creates a certificate request which is used to generate
// a CSR (Certificate Signing Request)
func (c *Client) newCertificateRequest(req *api.CSRInfo, id string) *csr.CertificateRequest {
	cr := &csr.CertificateRequest{CN: id}

	if req != nil {
		cr.Names = req.Names
		cr.Hosts = req.Hosts
		cr.CA = req.CA
		cr.SerialNumber = req.SerialNumber

		keyRequest := req.KeyRequest
		if keyRequest == nil || (keyRequest.Size == 0 && keyRequest.Algo == "") {
			keyRequest = api.NewKeyRequest()
		}
		cr.KeyRequest = newCfsslKeyRequest(keyRequest)

		return cr
	}

	// Default requested hosts are local hostname
	hostname, _ := os.Hostname()
	if hostname != "" {
		cr.Hosts = []string{hostname}
	}

	cr.KeyRequest = newCfsslKeyRequest(api.NewKeyRequest())

	return cr
}

func newCfsslKeyRequest(bkr *api.KeyRequest) *csr.KeyRequest {
	return &csr.KeyRequest{A: bkr.Algo, S: bkr.Size}
}

// generateCSPSigner generates a crypto.Signer for a given certificate request.
// If a key is not provided, a new one will be generated.
func (c *Client) generateCSPSigner(cr *csr.CertificateRequest, key bccsp.Key) (crypto.Signer, bccsp.Key, error) {
	if key == nil {
		// generate new key
		key, cspSigner, err := util.BCCSPKeyRequestGenerate(cr, c.csp)
		if err != nil {
			log.Debugf("failed generating BCCSP key: %s", err)
			return nil, nil, err
		}
		return cspSigner, key, nil
	}

	// use existing key
	log.Debugf("generating signer with existing key: %s", hex.EncodeToString(key.SKI()))
	cspSigner, err := NewSigner(c.csp, key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
	}

	return cspSigner, key, nil
}
