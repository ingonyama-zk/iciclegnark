// Copyright 2023 Ingonyama
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bls12377

import (
	"fmt"
	"testing"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"github.com/stretchr/testify/assert"
)

func TestFieldBN254FromGnark(t *testing.T) {
	var rand fr.Element
	rand.SetRandom()

	f := NewFieldFromFrGnark(rand)

	assert.Equal(t, f.S, icicle.ConvertUint64ArrToUint32Arr4(rand.Bits()))
}

func BenchmarkBatchConvertFromFrGnarkThreaded(b *testing.B) {
	// ROUTINES := []int{4,5,6,7,8}

	// for _, routineAmount := range ROUTINES {
	routineAmount := 7
	_, scalars_fr := GenerateScalars(1<<24, false)
	b.Run(fmt.Sprintf("Convert %d", routineAmount), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = BatchConvertFromFrGnarkThreaded(scalars_fr, routineAmount)
		}
	})
	// }
}

func BenchmarkBatchConvertFromFrGnark(b *testing.B) {
	_, scalars_fr := GenerateScalars(1<<24, false)
	b.Run("BatchConvert 2^24", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = BatchConvertFromFrGnark(scalars_fr)
		}
	})
}

func TestPointBN254FromGnark(t *testing.T) {
	gnarkP, _ := randG1Jac()

	var f icicle.G1BaseField
	f.SetOne()
	var p icicle.G1ProjectivePoint
	G1ProjectivePointFromJacGnark(&p, &gnarkP)

	z_inv := new(fp.Element)
	z_invsq := new(fp.Element)
	z_invq3 := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	z_inv.Inverse(&gnarkP.Z)
	z_invsq.Mul(z_inv, z_inv)
	z_invq3.Mul(z_invsq, z_inv)

	x.Mul(&gnarkP.X, z_invsq)
	y.Mul(&gnarkP.Y, z_invq3)

	assert.Equal(t, p.X, *NewFieldFromFpGnark(*x))
	assert.Equal(t, p.Y, *NewFieldFromFpGnark(*y))
	assert.Equal(t, p.Z, f)
}

func TestPointAffineNoInfinityBN254ToProjective(t *testing.T) {
	gnarkP, _ := randG1Jac()
	var f icicle.G1BaseField
	var p icicle.G1ProjectivePoint

	f.SetOne()
	affine := G1ProjectivePointFromJacGnark(&p, &gnarkP).StripZ()
	proj := affine.ToProjective()

	assert.Equal(t, proj.X, affine.X)
	assert.Equal(t, proj.X, affine.X)
	assert.Equal(t, proj.Z, f)
}

func TestToGnarkAffine(t *testing.T) {
	gJac, _ := randG1Jac()
	var proj icicle.G1ProjectivePoint
	G1ProjectivePointFromJacGnark(&proj, &gJac)

	var gAffine bls12377.G1Affine
	gAffine.FromJacobian(&gJac)

	affine := ProjectiveToGnarkAffine(&proj)
	assert.Equal(t, affine, gAffine)
}
