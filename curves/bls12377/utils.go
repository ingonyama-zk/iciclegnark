package bls12377

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
)

func ScalarToGnarkFr(f *icicle.G1ScalarField) *fr.Element {
	fb := f.ToBytesLe()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fr.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func ScalarToGnarkFp(f *icicle.G1ScalarField) *fp.Element {
	fb := f.ToBytesLe()
	var b32 [48]byte
	copy(b32[:], fb[:48])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func ProjectiveToGnarkAffine(p *icicle.G1ProjectivePoint) *bls12377.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bls12377.G1Affine{X: *x, Y: *y}
}

func G1ProjectivePointToGnarkJac(p *icicle.G1ProjectivePoint) *bls12377.G1Jac {
	var p1 bls12377.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func FromG1AffineGnark(gnark *bls12377.G1Affine, p *icicle.G1ProjectivePoint) *icicle.G1ProjectivePoint {
	var z icicle.G1BaseField
	z.SetOne()

	p.X = *NewFieldFromFpGnark(gnark.X)
	p.Y = *NewFieldFromFpGnark(gnark.Y)
	p.Z = z

	return p
}

func G1ProjectivePointFromJacGnark(p *icicle.G1ProjectivePoint, gnark *bls12377.G1Jac) *icicle.G1ProjectivePoint {
	var pointAffine bls12377.G1Affine
	pointAffine.FromJacobian(gnark)

	var z icicle.G1BaseField
	z.SetOne()

	p.X = *NewFieldFromFpGnark(pointAffine.X)
	p.Y = *NewFieldFromFpGnark(pointAffine.Y)
	p.Z = z

	return p
}

func AffineToGnarkAffine(p *icicle.G1PointAffine) *bls12377.G1Affine {
	return ProjectiveToGnarkAffine(p.ToProjective())
}

func BatchConvertFromFrGnark(elements []fr.Element) []icicle.G1ScalarField {
	var newElements []icicle.G1ScalarField
	for _, e := range elements {
		converted := NewFieldFromFrGnark(e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertFromFrGnarkThreaded(elements []fr.Element, routines int) []icicle.G1ScalarField {
	var newElements []icicle.G1ScalarField

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []icicle.G1ScalarField, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []icicle.G1ScalarField, 1)
		}

		convert := func(elements []fr.Element, chanIndex int) {
			var convertedElements []icicle.G1ScalarField
			for _, e := range elements {
				converted := NewFieldFromFrGnark(e)
				convertedElements = append(convertedElements, *converted)
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
			converted := NewFieldFromFrGnark(e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func BatchConvertG1BaseFieldToFrGnark(elements []icicle.G1BaseField) []fr.Element {
	var newElements []fr.Element
	for _, e := range elements {
		converted := BaseFieldToGnarkFr(&e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertG1ScalarFieldToFrGnark(elements []icicle.G1ScalarField) []fr.Element {
	var newElements []fr.Element
	for _, e := range elements {
		converted := ScalarToGnarkFr(&e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertG1BaseFieldToFrGnarkThreaded(elements []icicle.G1BaseField, routines int) []fr.Element {
	var newElements []fr.Element

	if routines > 1 {
		channels := make([]chan []fr.Element, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []fr.Element, 1)
		}

		convert := func(elements []icicle.G1BaseField, chanIndex int) {
			var convertedElements []fr.Element
			for _, e := range elements {
				converted := BaseFieldToGnarkFr(&e)
				convertedElements = append(convertedElements, *converted)
			}

			channels[chanIndex] <- convertedElements
		}

		batchLen := len(elements) / routines
		for i := 0; i < routines; i++ {
			elemsToConv := elements[batchLen*i : batchLen*(i+1)]
			go convert(elemsToConv, i)
		}

		for i := 0; i < routines; i++ {
			newElements = append(newElements, <-channels[i]...)
		}
	} else {
		for _, e := range elements {
			converted := BaseFieldToGnarkFr(&e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func BatchConvertG1ScalarFieldToFrGnarkThreaded(elements []icicle.G1ScalarField, routines int) []fr.Element {
	var newElements []fr.Element

	if routines > 1 {
		channels := make([]chan []fr.Element, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []fr.Element, 1)
		}

		convert := func(elements []icicle.G1ScalarField, chanIndex int) {
			var convertedElements []fr.Element
			for _, e := range elements {
				converted := ScalarToGnarkFr(&e)
				convertedElements = append(convertedElements, *converted)
			}

			channels[chanIndex] <- convertedElements
		}

		batchLen := len(elements) / routines
		for i := 0; i < routines; i++ {
			elemsToConv := elements[batchLen*i : batchLen*(i+1)]
			go convert(elemsToConv, i)
		}

		for i := 0; i < routines; i++ {
			newElements = append(newElements, <-channels[i]...)
		}
	} else {
		for _, e := range elements {
			converted := ScalarToGnarkFr(&e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func BatchConvertFromG1Affine(elements []bls12377.G1Affine) []icicle.G1PointAffine {
	var newElements []icicle.G1PointAffine
	for _, e := range elements {
		var newElement icicle.G1ProjectivePoint
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *newElement.StripZ())
	}
	return newElements
}

func NewFieldFromFrGnark(element fr.Element) *icicle.G1ScalarField {
	S := icicle.ConvertUint64ArrToUint32Arr4(element.Bits()) // get non-montgomry

	return &icicle.G1ScalarField{S}
}

func NewFieldFromFpGnark(element fp.Element) *icicle.G1BaseField {
	S := icicle.ConvertUint64ArrToUint32Arr6(element.Bits()) // get non-montgomry

	return &icicle.G1BaseField{S}
}

func BaseFieldToGnarkFr(f *icicle.G1BaseField) *fr.Element {
	fb := f.ToBytesLe()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fr.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func BaseFieldToGnarkFp(f *icicle.G1BaseField) *fp.Element {
	fb := f.ToBytesLe()
	var b32 [48]byte
	copy(b32[:], fb[:48])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}
