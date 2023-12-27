package bw6761

import (
	"encoding/binary"
	"github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bw6761"
)

func BatchConvertFromG1Affine(elements []bw6761.G1Affine) []icicle.G1PointAffine {
	var newElements []icicle.G1PointAffine
	for _, e := range elements {
		var newElement icicle.G1ProjectivePoint
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *newElement.StripZ())
	}
	return newElements
}

func ProjectiveToGnarkAffine(p *icicle.G1ProjectivePoint) *bw6761.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bw6761.G1Affine{X: *x, Y: *y}
}

func G1ProjectivePointToGnarkJac(p *icicle.G1ProjectivePoint) *bw6761.G1Jac {
	var p1 bw6761.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func FromG1AffineGnark(gnark *bw6761.G1Affine, p *icicle.G1ProjectivePoint) *icicle.G1ProjectivePoint {
	var z icicle.G1BaseField
	z.SetOne()

	p.X = *NewFieldFromFpGnark(gnark.X)
	p.Y = *NewFieldFromFpGnark(gnark.Y)
	p.Z = z

	return p
}

func G1ProjectivePointFromJacGnark(p *icicle.G1ProjectivePoint, gnark *bw6761.G1Jac) *icicle.G1ProjectivePoint {
	var pointAffine bw6761.G1Affine
	pointAffine.FromJacobian(gnark)

	var z icicle.G1BaseField
	z.SetOne()

	p.X = *NewFieldFromFpGnark(pointAffine.X)
	p.Y = *NewFieldFromFpGnark(pointAffine.Y)
	p.Z = z

	return p
}

func AffineToGnarkAffine(p *icicle.G1PointAffine) *bw6761.G1Affine {
	return ProjectiveToGnarkAffine(p.ToProjective())
}

func ConvertUint64ArrToUint32Arr6(arr64 [6]uint64) [12]uint32 {
	var arr32 [12]uint32
	for i, v := range arr64 {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)

		arr32[i*2] = binary.LittleEndian.Uint32(b[0:4])
		arr32[i*2+1] = binary.LittleEndian.Uint32(b[4:8])
	}

	return arr32
}

func ConvertUint64ArrToUint32Arr12(arr64 [12]uint64) [24]uint32 {
	var arr32 [24]uint32
	for i, v := range arr64 {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)

		arr32[i*2] = binary.LittleEndian.Uint32(b[0:4])
		arr32[i*2+1] = binary.LittleEndian.Uint32(b[4:8])
	}

	return arr32
}
