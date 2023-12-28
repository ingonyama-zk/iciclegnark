package bw6761

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bw6761"
)

func ToGnarkE2(f *icicle.G2Element) *fp.Element {
	fb := f.ToBytesLe()
	var b96 [96]byte
	copy(b96[:], fb[:96])

	v, e := fp.LittleEndian.Element(&b96)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v got error %v", f, e))
	}

	return &v
}

func G2PointToGnarkJac(p *icicle.G2Point) *bw6761.G2Jac {
	x := ToGnarkE2(&p.X)
	y := ToGnarkE2(&p.Y)
	z := ToGnarkE2(&p.Z)
	var zSquared fp.Element
	zSquared.Mul(z, z)

	var X fp.Element
	X.Mul(x, z)

	var Y fp.Element
	Y.Mul(y, &zSquared)

	after := bw6761.G2Jac{
		X: X,
		Y: Y,
		Z: *z,
	}

	return &after
}

func G2AffineFromGnarkAffine(gnark *bw6761.G2Affine, g *icicle.G2PointAffine) *icicle.G2PointAffine {
	g.X = gnark.X.Bits()
	g.Y = gnark.Y.Bits()
	return g
}

func G2PointAffineFromGnarkJac(gnark *bw6761.G2Jac, g *icicle.G2PointAffine) *icicle.G2PointAffine {
	var pointAffine bw6761.G2Affine
	pointAffine.FromJacobian(gnark)

	g.X = pointAffine.X.Bits()
	g.X = pointAffine.X.Bits()
	g.Y = pointAffine.Y.Bits()
	g.Y = pointAffine.Y.Bits()

	return g
}

func BatchConvertFromG2Affine(elements []bw6761.G2Affine) []icicle.G2PointAffine {
	var newElements []icicle.G2PointAffine
	for _, gg2Affine := range elements {
		var newElement icicle.G2PointAffine
		G2AffineFromGnarkAffine(&gg2Affine, &newElement)

		newElements = append(newElements, newElement)
	}
	return newElements
}

func BatchConvertFromG2AffineThreads(elements []bw6761.G2Affine, routines int) []icicle.G2PointAffine {
	var newElements []icicle.G2PointAffine

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []icicle.G2PointAffine, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []icicle.G2PointAffine, 1)
		}

		convert := func(elements []bw6761.G2Affine, chanIndex int) {
			var convertedElements []icicle.G2PointAffine
			for _, e := range elements {
				var converted icicle.G2PointAffine
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
			var converted icicle.G2PointAffine
			G2AffineFromGnarkAffine(&e, &converted)
			newElements = append(newElements, converted)
		}
	}

	return newElements
}
