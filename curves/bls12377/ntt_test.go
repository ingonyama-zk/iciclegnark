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
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/fft"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"github.com/stretchr/testify/assert"
)

func TestNttBN254BBB(t *testing.T) {
	count := 1 << 20
	scalars, frScalars := GenerateScalars(count, false)

	nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
	copy(nttResult, scalars)

	assert.Equal(t, nttResult, scalars)
	icicle.NttBatch(&nttResult, false, count, 0)
	assert.NotEqual(t, nttResult, scalars)

	domain := fft.NewDomain(uint64(len(scalars)))
	// DIT WITH NO INVERSE
	// DIF WITH INVERSE
	domain.FFT(frScalars, fft.DIT) //DIF

	nttResultTransformedToGnark := make([]fr.Element, len(scalars)) // Make a new slice with the same length

	for k, v := range nttResult {
		nttResultTransformedToGnark[k] = *ScalarToGnarkFr(&v)
	}

	assert.Equal(t, nttResultTransformedToGnark, frScalars)
}

func TestNttBN254CompareToGnarkDIF(t *testing.T) {
	count := 1 << 2
	scalars, frScalars := GenerateScalars(count, false)

	nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
	copy(nttResult, scalars)

	assert.Equal(t, nttResult, scalars)
	icicle.Ntt(&nttResult, false, icicle.DIF, 0)
	assert.NotEqual(t, nttResult, scalars)

	domain := fft.NewDomain(uint64(len(scalars)))
	// DIT WITH NO INVERSE
	// DIF WITH INVERSE
	domain.FFT(frScalars, fft.DIF) //DIF

	nttResultTransformedToGnark := make([]fr.Element, len(scalars)) // Make a new slice with the same length

	for k, v := range nttResult {
		nttResultTransformedToGnark[k] = *ScalarToGnarkFr(&v)
	}

	assert.Equal(t, nttResultTransformedToGnark, frScalars)
}

func TestNttBN254CompareToGnarkDIT(t *testing.T) {
	count := 1 << 2
	scalars, frScalars := GenerateScalars(count, false)

	nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
	copy(nttResult, scalars)

	assert.Equal(t, nttResult, scalars)
	icicle.Ntt(&nttResult, false, icicle.DIT, 0)
	assert.NotEqual(t, nttResult, scalars)

	domain := fft.NewDomain(uint64(len(scalars)))
	// DIT WITH NO INVERSE
	// DIF WITH INVERSE
	domain.FFT(frScalars, fft.DIT) //DIF

	nttResultTransformedToGnark := make([]fr.Element, len(scalars)) // Make a new slice with the same length

	for k, v := range nttResult {
		nttResultTransformedToGnark[k] = *ScalarToGnarkFr(&v)
	}

	assert.Equal(t, nttResultTransformedToGnark, frScalars)
}

func TestINttBN254CompareToGnarkDIT(t *testing.T) {
	count := 1 << 3
	scalars, frScalars := GenerateScalars(count, false)

	nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
	copy(nttResult, scalars)

	assert.Equal(t, nttResult, scalars)
	icicle.Ntt(&nttResult, true, icicle.DIT, 0)
	assert.NotEqual(t, nttResult, scalars)

	frResScalars := make([]fr.Element, len(frScalars)) // Make a new slice with the same length
	copy(frResScalars, frScalars)

	domain := fft.NewDomain(uint64(len(scalars)))
	domain.FFTInverse(frResScalars, fft.DIT)

	assert.NotEqual(t, frResScalars, frScalars)

	nttResultTransformedToGnark := make([]fr.Element, len(scalars)) // Make a new slice with the same length

	for k, v := range nttResult {
		nttResultTransformedToGnark[k] = *ScalarToGnarkFr(&v)
	}

	assert.Equal(t, nttResultTransformedToGnark, frResScalars)
}

func TestINttBN254CompareToGnarkDIF(t *testing.T) {
	count := 1 << 3
	scalars, frScalars := GenerateScalars(count, false)

	nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
	copy(nttResult, scalars)

	assert.Equal(t, nttResult, scalars)
	icicle.Ntt(&nttResult, true, icicle.DIF, 0)
	assert.NotEqual(t, nttResult, scalars)

	domain := fft.NewDomain(uint64(len(scalars)))
	domain.FFTInverse(frScalars, fft.DIF)

	nttResultTransformedToGnark := make([]fr.Element, len(scalars)) // Make a new slice with the same length

	for k, v := range nttResult {
		nttResultTransformedToGnark[k] = *ScalarToGnarkFr(&v)
	}

	assert.Equal(t, nttResultTransformedToGnark, frScalars)
}

func TestNttBN254(t *testing.T) {
	count := 1 << 3

	scalars, _ := GenerateScalars(count, false)

	nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
	copy(nttResult, scalars)

	assert.Equal(t, nttResult, scalars)
	icicle.Ntt(&nttResult, false, icicle.NONE, 0)
	assert.NotEqual(t, nttResult, scalars)

	inttResult := make([]icicle.G1ScalarField, len(nttResult))
	copy(inttResult, nttResult)

	assert.Equal(t, inttResult, nttResult)
	icicle.Ntt(&inttResult, true, icicle.NONE, 0)
	assert.Equal(t, inttResult, scalars)
}

func TestNttBatchBN254(t *testing.T) {
	count := 1 << 5
	batches := 4

	scalars, _ := GenerateScalars(count*batches, false)

	var scalarVecOfVec [][]icicle.G1ScalarField = make([][]icicle.G1ScalarField, 0)

	for i := 0; i < batches; i++ {
		start := i * count
		end := (i + 1) * count
		batch := make([]icicle.G1ScalarField, len(scalars[start:end]))
		copy(batch, scalars[start:end])
		scalarVecOfVec = append(scalarVecOfVec, batch)
	}

	nttBatchResult := make([]icicle.G1ScalarField, len(scalars))
	copy(nttBatchResult, scalars)

	icicle.NttBatch(&nttBatchResult, false, count, 0)

	var nttResultVecOfVec [][]icicle.G1ScalarField

	for i := 0; i < batches; i++ {
		// Clone the slice
		clone := make([]icicle.G1ScalarField, len(scalarVecOfVec[i]))
		copy(clone, scalarVecOfVec[i])

		// Add it to the result vector of vectors
		nttResultVecOfVec = append(nttResultVecOfVec, clone)

		// Call the ntt_bls12377 function
		icicle.Ntt(&nttResultVecOfVec[i], false, icicle.NONE, 0)
	}

	assert.NotEqual(t, nttBatchResult, scalars)

	// Check that the ntt of each vec of scalars is equal to the intt of the specific batch
	for i := 0; i < batches; i++ {
		if !reflect.DeepEqual(nttResultVecOfVec[i], nttBatchResult[i*count:((i+1)*count)]) {
			t.Errorf("ntt of vec of scalars not equal to intt of specific batch")
		}
	}
}

func BenchmarkNTT(b *testing.B) {
	LOG_NTT_SIZES := []int{12, 15, 20, 21, 22, 23, 24, 25, 26}

	for _, logNTTSize := range LOG_NTT_SIZES {
		nttSize := 1 << logNTTSize
		b.Run(fmt.Sprintf("NTT %d", logNTTSize), func(b *testing.B) {
			scalars, _ := GenerateScalars(nttSize, false)

			nttResult := make([]icicle.G1ScalarField, len(scalars)) // Make a new slice with the same length
			copy(nttResult, scalars)
			for n := 0; n < b.N; n++ {
				icicle.Ntt(&nttResult, false, icicle.NONE, 0)
			}
		})
	}
}
