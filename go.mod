module github.com/mkhattat/frost

go 1.20

// replace github.com/hyperledger/fabric-ca v1.5.6 => github.com/johannww/fabric-ca v0.0.0-20230102042314-bada340eab89

// replace github.com/hyperledger/fabric v1.4.11 => github.com/johannww/fabric-1 v0.0.0-20221130143147-4c6de157c5c4
replace github.com/hyperledger/fabric v1.4.11 => github.com/johannww/fabric-1 v0.0.0-20221130143147-4c6de157c5c4

require (
	filippo.io/edwards25519 v1.0.0
	github.com/IBM/idemix v0.0.2-0.20230510082947-a0c3ee5ebe35
	github.com/IBM/mathlib v0.0.3-0.20230428120512-8afa4e643d4c
	github.com/bytemare/crypto v0.5.1
	github.com/bytemare/hash v0.1.5
	github.com/bytemare/secret-sharing v0.1.0
	github.com/cloudflare/cfssl v1.4.1
	github.com/gtank/ristretto255 v0.1.2
	github.com/hyperledger/fabric v1.4.11
	github.com/hyperledger/fabric-ca v1.5.7
	github.com/pkg/errors v0.9.1
)

require (
	filippo.io/nistec v0.0.2 // indirect
	github.com/bytemare/hash2curve v0.1.3 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.9.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/golang/protobuf v1.5.0 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/jmhodges/clock v0.0.0-20160418191101-880ee4c33548 // indirect
	github.com/jmoiron/sqlx v1.2.0 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/kisielk/sqlstruct v0.0.0-20201105191214-5f3e10d3ab46 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.1.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.3.2 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	github.com/weppos/publicsuffix-go v0.5.0 // indirect
	github.com/zmap/zcrypto v0.0.0-20190729165852-9051775e6a2e // indirect
	github.com/zmap/zlint v0.0.0-20190806154020-fd021b4cfbeb // indirect
	go.uber.org/atomic v1.6.0 // indirect
	go.uber.org/multierr v1.5.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	google.golang.org/grpc v1.31.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
