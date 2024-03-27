package bn254

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	core "github.com/ingonyama-zk/icicle/wrappers/golang/core"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func Ntt[T any](gnarkScalars fr.Vector, dir core.NTTDir, cfg *core.NTTConfig[T]) fr.Vector {
	icicleScalars := core.HostSliceFromElements(BatchConvertFromFrGnark[icicle_bn254.ScalarField](gnarkScalars))
	output := make(core.HostSlice[icicle_bn254.ScalarField], len(gnarkScalars))
	res := icicle_bn254.Ntt(icicleScalars, core.KForward, cfg, output)
	if res.IcicleErrorCode != core.IcicleErrorCode(0) {
		fmt.Print("Issue evaluating")
	}
	// TODO Reverse order processing
	// if cfg.Ordering == core.KNN || cfg.Ordering == core.KRR {

	// }
	return BatchConvertG1ScalarFieldToFrGnark(output)
}

func NttOnDevice(gnarkScalars fr.Vector) fr.Vector {
	cfg := icicle_bn254.GetDefaultNttConfig()
	return Ntt(gnarkScalars, core.KForward, &cfg)
}

func INttOnDevice(gnarkScalars fr.Vector) fr.Vector {
	cfg := icicle_bn254.GetDefaultNttConfig()
	return Ntt(gnarkScalars, core.KInverse, &cfg)
}
