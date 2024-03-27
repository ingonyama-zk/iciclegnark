package bn254

import (
	"unsafe"
)

type OnDeviceData struct {
	P    unsafe.Pointer
	Size int
}

// func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) unsafe.Pointer {
// 	ReverseScalars(scalars_d, size)

// 	scalarsInterp := icicle_bn254.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)

// 	return scalarsInterp
// }

// func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) {
// 	res := icicle_bn254.Ntt(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)

// 	if res.IcicleErrorCode != core.IcicleErrorCode(0) {
// 		fmt.Print("Issue evaluating")
// 	}

// 	ReverseScalars(scalars_out, size)
// }

// func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count int, convert bool) (bn254.G1Jac, unsafe.Pointer, error) {
// 	var p icicle_bn254.Projective
// 	var out_d core.DeviceSlice
// 	_, e := out_d.Malloc(p.Size(), p.Size())
// 	if e != cr.CudaSuccess {
// 		return bn254.G1Jac{}, nil, errors.New("Allocation error")
// 	}

// 	icicle_bn254.Msm((s))

// 	icicle_bn254.Msm(out_d, scalars_d, points_d, count, 10)

// 	if convert {
// 		outHost := make([]icicle_bn254.Projective, 1)
// 		cr.CopyFromDevice(outHost, out_d, uint(pointBytes))

// 		return *G1ProjectivePointToGnarkJac(&outHost[0]), nil, nil
// 	}

// 	return bn254.G1Jac{}, out_d, nil
// }

// func GenerateTwiddleFactors(size int, inverse bool) (unsafe.Pointer, error) {
// 	om_selector := int(math.Log(float64(size)) / math.Log(2))
// 	return icicle_bn254.GenerateTwiddles(size, om_selector, inverse)
// }

// func ReverseScalars(ptr unsafe.Pointer, size int) error {
// 	if success, err := icicle_bn254.ReverseScalars(ptr, size); success != 0 {
// 		return err
// 	}

// 	return nil
// }

// func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) {
// 	ret := icicle_bn254.VecScalarMulMod(a_d, b_d, size)

// 	if ret != 0 {
// 		fmt.Print("Vector mult a*b issue")
// 	}
// 	ret = icicle_bn254.VecScalarSub(a_d, c_d, size)

// 	if ret != 0 {
// 		fmt.Print("Vector sub issue")
// 	}
// 	ret = icicle_bn254.VecScalarMulMod(a_d, den_d, size)

// 	if ret != 0 {
// 		fmt.Print("Vector mult a*den issue")
// 	}
// }

// func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) {
// 	if is_into {
// 		icicle_bn254.ToMontgomery(scalars_d, size)
// 	} else {
// 		icicle_bn254.FromMontgomery(scalars_d, size)
// 	}
// }
