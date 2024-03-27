package bn254

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	core "github.com/ingonyama-zk/icicle/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func MsmOnDevice(gnarkPoints []bn254.G1Affine, gnarkScalars []fr.Element) (*bn254.G1Affine, error) {
	iciclePoints := core.HostSliceFromElements(BatchConvertFromG1Affine(gnarkPoints))
	icicleScalars := core.HostSliceFromElements(BatchConvertFromFrGnark[icicle_bn254.ScalarField](gnarkScalars))

	cfg := core.GetDefaultMSMConfig()
	var p icicle_bn254.Projective
	var out core.DeviceSlice
	_, e := out.Malloc(p.Size(), p.Size())
	if e != cr.CudaSuccess {
		return nil, errors.New("cannot allocate")
	}
	e = icicle_bn254.Msm(icicleScalars, iciclePoints, &cfg, out)
	if e != cr.CudaSuccess {
		return nil, errors.New("msm failed")
	}
	outHost := make(core.HostSlice[icicle_bn254.Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()
	return ProjectiveToGnarkAffine(&outHost[0]), nil
}
