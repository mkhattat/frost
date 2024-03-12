/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package mycsr

import (
	"crypto"
	"fmt"
	"io"

	"github.com/hyperledger/fabric/bccsp"
)

// bccspCryptoSigner is the BCCSP-based implementation of a crypto.Signer
type bccspCryptoSigner struct {
	csp    bccsp.BCCSP
	key    bccsp.Key
	pk     interface{}
	config *ClientConfig
}

// New returns a new BCCSP-based crypto.Signer
// for the given BCCSP instance and key.
func NewSigner(csp bccsp.BCCSP, config *ClientConfig) (crypto.Signer, error) {
	return &bccspCryptoSigner{csp, nil, config.PK, config}, nil
}

// Public returns the public key corresponding to the opaque,
// private key.
func (s *bccspCryptoSigner) Public() crypto.PublicKey {
	fmt.Printf(">>>>>>>public key %+v\n", s.pk)
	return s.pk
}

// Sign signs digest with the private key, possibly using entropy from
// rand. For an RSA key, the resulting signature should be either a
// PKCS#1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
// key, it should be a DER-serialised, ASN.1 signature structure.
//
// Hash implements the SignerOpts interface and, in most cases, one can
// simply pass in the hash function used as opts. Sign may also attempt
// to type assert opts to other types in order to obtain algorithm
// specific values. See the documentation in each package for details.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest) and the hash function (as opts) to Sign.
func (s *bccspCryptoSigner) Sign(rand io.Reader, digestOrMsg []byte, opts crypto.SignerOpts) ([]byte, error) {
	fmt.Printf(">>>>>>>start signing\n")
	return s.config.FrostSign(digestOrMsg), nil
}
