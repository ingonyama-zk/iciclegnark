package bls12377

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
)

func BatchConvertFromG1Affine(elements []bls12377.G1Affine) []icicle.G1PointAffine {
	var newElements []icicle.G1PointAffine
	for _, e := range elements {
		var newElement icicle.G1ProjectivePoint
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *newElement.StripZ())
	}
	return newElements
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
