//go:build g2

package bn254

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/ingonyama-zk/icicle/wrappers/golang/core"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func ToGnarkFp(f *icicle_bn254.G2BaseField) *fp.Element {
	fb := f.ToBytesLittleEndian()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v; got error %v", f, e))
	}

	return &v
}

func ToGnarkE2(f *icicle_bn254.G2BaseField) bn254.E2 {
	bytes := f.ToBytesLittleEndian()
	a0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(bytes[:f.Len()/2]))
	a1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(bytes[f.Len()/2:]))
	return bn254.E2{
		A0: a0,
		A1: a1,
	}
}

func GnarkE2Bits(f *bn254.E2) []uint64 {
	a0 := f.A0.Bits()
	a1 := f.A1.Bits()
	return append(a0[:], a1[:]...)
}

func FromGnarkE2(f *bn254.E2) icicle_bn254.G2BaseField {
	var field icicle_bn254.G2BaseField
	field.FromLimbs(core.ConvertUint64ArrToUint32Arr(GnarkE2Bits(f)))
	return field
}

func G2PointToGnarkJac(p *icicle_bn254.G2Projective) *bn254.G2Jac {
	x := ToGnarkE2(&p.X)
	y := ToGnarkE2(&p.Y)
	z := ToGnarkE2(&p.Z)
	var zSquared bn254.E2
	zSquared.Mul(&z, &z)

	var X bn254.E2
	X.Mul(&x, &z)

	var Y bn254.E2
	Y.Mul(&y, &zSquared)

	after := bn254.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	return &after
}

func G2PointToGnarkAffine(p *icicle_bn254.G2Projective) *bn254.G2Affine {
	var affine bn254.G2Affine
	affine.FromJacobian(G2PointToGnarkJac(p))
	return &affine
}

func G2AffineFromGnarkAffine(gnark *bn254.G2Affine, g *icicle_bn254.G2Affine) *icicle_bn254.G2Affine {
	g.X = FromGnarkE2(&gnark.X)
	g.Y = FromGnarkE2(&gnark.Y)
	return g
}

func G2PointAffineFromGnarkJac(gnark *bn254.G2Jac, g *icicle_bn254.G2Affine) *icicle_bn254.G2Affine {
	var pointAffine bn254.G2Affine
	pointAffine.FromJacobian(gnark)

	return G2AffineFromGnarkAffine(&pointAffine, g)
}

func BatchConvertFromG2Affine(elements []bn254.G2Affine) []icicle_bn254.G2Affine {
	var newElements []icicle_bn254.G2Affine
	for _, gg2Affine := range elements {
		var newElement icicle_bn254.G2Affine
		G2AffineFromGnarkAffine(&gg2Affine, &newElement)

		newElements = append(newElements, newElement)
	}
	return newElements
}

func BatchConvertFromG2AffineThreaded(elements []bn254.G2Affine, routines int) []icicle_bn254.G2Affine {
	var newElements []icicle_bn254.G2Affine

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []icicle_bn254.G2Affine, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []icicle_bn254.G2Affine, 1)
		}

		convert := func(elements []bn254.G2Affine, chanIndex int) {
			var convertedElements []icicle_bn254.G2Affine
			for _, e := range elements {
				var converted icicle_bn254.G2Affine
				G2AffineFromGnarkAffine(&e, &converted)
				convertedElements = append(convertedElements, converted)
			}

			channels[chanIndex] <- convertedElements
		}

		batchLen := len(elements) / routines
		for i := 0; i < routines; i++ {
			start := batchLen * i
			end := batchLen * (i + 1)
			elemsToConv := elements[start:end]
			if i == routines-1 {
				elemsToConv = elements[start:]
			}
			go convert(elemsToConv, i)
		}

		for i := 0; i < routines; i++ {
			newElements = append(newElements, <-channels[i]...)
		}
	} else {
		for _, e := range elements {
			var converted icicle_bn254.G2Affine
			G2AffineFromGnarkAffine(&e, &converted)
			newElements = append(newElements, converted)
		}
	}

	return newElements
}
