// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"testing"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/mkhattat/frost"
	"github.com/mkhattat/frost/dkg"
)

// testUnit holds a participant and its return and input values during the protocol.
type testUnit struct {
	participant       *dkg.Participant
	r1Data            *dkg.Round1Data
	secret            *group.Scalar
	verificationShare *group.Element
	publicKey         *group.Element
	r2OutputData      []*dkg.Round2Data
	r2InputData       []*dkg.Round2Data
}

func idFromInt(t *testing.T, g group.Group, i int) *group.Scalar {
	id, err := frost.IdFromInt(g, i)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// dkgGenerateKeys generates sharded keys for maxSigner participant without a trusted dealer, and returns these shares
// and the group's public key.
func dkgGenerateKeys(
	t *testing.T,
	conf *frost.Configuration,
	maxSigners, threshold int,
) ([]*secretsharing.KeyShare, *group.Element) {
	secretShares, groupPublicKey, err := frost.DkgGenerateKeys(conf, maxSigners, threshold)
	if err != nil {
		t.Fatal(err)
	}

	return secretShares, groupPublicKey
}

// TestDKG verifies
//   - execution of the protocol with any number of participants and threshold, and no errors.
//   - the correctness of each verification share.
//   - the correctness of the group public key.
//   - the correctness of the secret key recovery with regard to the public key.
func TestDKG(t *testing.T) {
	conf := frost.Ristretto255.Configuration()
	g := conf.Ciphersuite.Group
	maxSigners := 5
	quals := []int{1, 3, 5} // = threshold

	var err error

	// Vector of participant units.
	units := make([]*testUnit, maxSigners)
	for i := 0; i < maxSigners; i++ {
		id := idFromInt(t, conf.Ciphersuite.Group, i+1)
		units[i] = &testUnit{
			participant: dkg.NewParticipant(conf.Ciphersuite, id, maxSigners, len(quals)),
			r2InputData: make([]*dkg.Round2Data, 0, maxSigners-1),
		}
	}

	// Step 1: Init.
	for _, unit := range units {
		unit.r1Data = unit.participant.Init()
	}

	// Step 2: assemble packages.
	r1Data := make([]*dkg.Round1Data, maxSigners)
	for i, unit := range units {
		r1Data[i] = unit.r1Data
	}

	// Step 3: Continue.
	for _, unit := range units {
		unit.r2OutputData, err = unit.participant.Continue(r1Data)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Step 4: assemble packages.
	for i, uniti := range units {
		for j, unitj := range units {
			if i == j {
				continue
			}

			for _, p := range unitj.r2OutputData {
				if p.ReceiverIdentifier.Equal(uniti.participant.Identifier) == 1 {
					uniti.r2InputData = append(uniti.r2InputData, p)
					break
				}
			}
		}
	}

	// Step 5: Finalize.
	for _, unit := range units {
		unit.secret, unit.verificationShare, unit.publicKey, err = unit.participant.Finalize(
			r1Data,
			unit.r2InputData,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify individual verification shares.
	for _, unit := range units {
		verifPk := dkg.ComputeVerificationShare(g, unit.participant.Identifier, r1Data)
		if verifPk.Equal(unit.verificationShare) != 1 {
			t.Fatal("invalid verification key")
		}
	}

	// Compare group public keys.
	p1g := units[0].publicKey
	for _, unit := range units[1:] {
		if p1g.Equal(unit.publicKey) != 1 {
			t.Fatal("expected equality")
		}
	}

	// Verify the individual secret shares by combining a subset of them.
	keyShares := make([]*secretsharing.KeyShare, len(quals))
	for i, ii := range quals {
		id := idFromInt(t, conf.Ciphersuite.Group, ii)

		for _, unit := range units {
			if id.Equal(unit.participant.Identifier) == 1 {
				keyShares[i] = &secretsharing.KeyShare{
					Identifier: unit.participant.Identifier,
					SecretKey:  unit.secret,
				}
			}
		}
	}

	secret, err := secretsharing.Combine(g, uint(len(quals)), keyShares)
	if err != nil {
		t.Fatal(err)
	}

	pk := g.Base().Multiply(secret)
	if pk.Equal(p1g) != 1 {
		t.Fatal("expected recovered secret to be compatible with public key")
	}
}

// TestDKG_InvalidPOK verifies whether an invalid signature is detected and an error is returned.
func TestDKG_InvalidPOK(t *testing.T) {
	conf := frost.Ristretto255.Configuration()
	g := conf.Ciphersuite.Group

	maxSigners := 2
	threshold := 1

	one := g.NewScalar().One()
	p1 := dkg.NewParticipant(conf.Ciphersuite, one, maxSigners, threshold)

	two := g.NewScalar().One().Add(g.NewScalar().One())
	p2 := dkg.NewParticipant(conf.Ciphersuite, two, maxSigners, threshold)

	r1P1 := p1.Init()
	r1P2 := p2.Init()

	r1P2.ProofOfKnowledge.Z = g.NewScalar().Random()

	r1Data := []*dkg.Round1Data{r1P1, r1P2}

	if _, err := p1.Continue(r1Data); err == nil {
		t.Fatal("expected error on invalid signature")
	}
}
