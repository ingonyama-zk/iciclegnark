package bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func StripZ(p *icicle_bn254.Projective) *icicle_bn254.Affine {
	return &icicle_bn254.Affine{
		X: p.X,
		Y: p.Y,
	}
}

func BatchConvertFromG1Affine(elements []bn254.G1Affine) []icicle_bn254.Affine {
	var newElements []icicle_bn254.Affine
	for _, e := range elements {
		var newElement icicle_bn254.Projective
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *StripZ(&newElement))
	}
	return newElements
}

func ProjectiveToGnarkAffine(p *icicle_bn254.Projective) *bn254.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bn254.G1Affine{X: *x, Y: *y}
}

func G1ProjectivePointToGnarkJac(p *icicle_bn254.Projective) *bn254.G1Jac {
	var p1 bn254.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func FromG1AffineGnark(gnark *bn254.G1Affine, p *icicle_bn254.Projective) *icicle_bn254.Projective {
	var z icicle_bn254.BaseField
	z.One()

	p.X = *NewFieldFromFpGnark[icicle_bn254.BaseField](gnark.X)
	p.Y = *NewFieldFromFpGnark[icicle_bn254.BaseField](gnark.Y)
	p.Z = z

	return p
}

func G1ProjectivePointFromJacGnark(p *icicle_bn254.Projective, gnark *bn254.G1Jac) *icicle_bn254.Projective {
	var pointAffine bn254.G1Affine
	pointAffine.FromJacobian(gnark)

	var z icicle_bn254.BaseField
	z.One()

	p.X = *NewFieldFromFpGnark[icicle_bn254.BaseField](pointAffine.X)
	p.Y = *NewFieldFromFpGnark[icicle_bn254.BaseField](pointAffine.Y)
	p.Z = z

	return p
}

func AffineToGnarkAffine(p *icicle_bn254.Affine) *bn254.G1Affine {
	pointProjective := p.ToProjective()
	return ProjectiveToGnarkAffine(&pointProjective)
}
