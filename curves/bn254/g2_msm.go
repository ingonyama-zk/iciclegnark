//go:build g2

package bn254

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	core "github.com/ingonyama-zk/icicle/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func G2MsmOnDevice(gnarkPoints []bn254.G2Affine, gnarkScalars []fr.Element) (*bn254.G2Affine, error) {
	iciclePoints := core.HostSliceFromElements(BatchConvertFromG2Affine(gnarkPoints))
	icicleScalars := core.HostSliceFromElements(BatchConvertFromFrGnark[icicle_bn254.ScalarField](gnarkScalars))

	cfg := core.GetDefaultMSMConfig()
	var p icicle_bn254.G2Projective
	var out core.DeviceSlice
	_, e := out.Malloc(p.Size(), p.Size())
	if e != cr.CudaSuccess {
		return nil, errors.New("Cannot allocate")
	}
	e = icicle_bn254.G2Msm(icicleScalars, iciclePoints, &cfg, out)
	if e != cr.CudaSuccess {
		return nil, errors.New("Msm failed")
	}
	outHost := make(core.HostSlice[icicle_bn254.G2Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()
	return G2PointToGnarkAffine(&outHost[0]), nil
}
