package bn254

import (
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	core "github.com/ingonyama-zk/icicle/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

// func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
// 	devicePtr, _ := cr.Malloc(uint(bytes))
// 	cr.CopyToDevice(devicePtr, unsafe.Pointer(&scalars[0]), uint(bytes))
// 	MontConvOnDevice(devicePtr, len(scalars), false)

// 	copyDone <- devicePtr
// }

// func CopyPointsToDevice(points []bn254.G1Affine, pointsBytes int, copyDone chan unsafe.Pointer) {
// 	if pointsBytes == 0 {
// 		copyDone <- nil
// 	} else {
// 		devicePtr, _ := cr.Malloc(uint(pointsBytes))
// 		iciclePoints := BatchConvertFromG1Affine(points)
// 		cr.CopyToDevice(devicePtr, unsafe.Pointer(&iciclePoints[0]), uint(pointsBytes))

// 		copyDone <- devicePtr
// 	}
// }

// func CopyG2PointsToDevice(points []bn254.G2Affine, pointsBytes int, copyDone chan unsafe.Pointer) {
// 	if pointsBytes == 0 {
// 		copyDone <- nil
// 	} else {
// 		devicePtr, _ := cr.Malloc(uint(pointsBytes))
// 		iciclePoints := BatchConvertFromG2Affine(points)
// 		cr.CopyToDevice(devicePtr, unsafe.Pointer(&iciclePoints[0]), uint(pointsBytes))

// 		copyDone <- devicePtr
// 	}
// }

func FreeDevicePointer(ptr unsafe.Pointer) {
	cr.Free(ptr)
}

func ScalarToGnarkFr(f *icicle_bn254.ScalarField) *fr.Element {
	fb := f.ToBytesLittleEndian()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fr.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func ScalarToGnarkFp(f *icicle_bn254.ScalarField) *fp.Element {
	fb := f.ToBytesLittleEndian()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func BatchConvertFromFrGnark[T icicle_bn254.BaseField | icicle_bn254.ScalarField](elements []fr.Element) []T {
	var newElements []T
	for _, e := range elements {
		converted := NewFieldFromFrGnark[T](e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertFromFrGnarkThreaded[T icicle_bn254.BaseField | icicle_bn254.ScalarField](elements []fr.Element, routines int) []T {
	var newElements []T

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []T, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []T, 1)
		}

		convert := func(elements []fr.Element, chanIndex int) {
			var convertedElements []T
			for _, e := range elements {
				converted := NewFieldFromFrGnark[T](e)
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
			converted := NewFieldFromFrGnark[T](e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func BatchConvertG1BaseFieldToFrGnark(elements []icicle_bn254.BaseField) []fr.Element {
	var newElements []fr.Element
	for _, e := range elements {
		converted := BaseFieldToGnarkFr(&e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertG1ScalarFieldToFrGnark(elements []icicle_bn254.ScalarField) []fr.Element {
	var newElements []fr.Element
	for _, e := range elements {
		converted := ScalarToGnarkFr(&e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertG1BaseFieldToFrGnarkThreaded(elements []icicle_bn254.BaseField, routines int) []fr.Element {
	var newElements []fr.Element

	if routines > 1 {
		channels := make([]chan []fr.Element, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []fr.Element, 1)
		}

		convert := func(elements []icicle_bn254.BaseField, chanIndex int) {
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

func BatchConvertG1ScalarFieldToFrGnarkThreaded(elements []icicle_bn254.ScalarField, routines int) []fr.Element {
	var newElements []fr.Element

	if routines > 1 {
		channels := make([]chan []fr.Element, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []fr.Element, 1)
		}

		convert := func(elements []icicle_bn254.ScalarField, chanIndex int) {
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

func NewFieldFromFrGnark[T icicle_bn254.BaseField | icicle_bn254.ScalarField](element fr.Element) *T {
	element_bits := element.Bits()
	s := core.ConvertUint64ArrToUint32Arr(element_bits[:]) // get non-montgomry

	var field T
	switch any(field).(type) {
	case icicle_bn254.BaseField:
		var base icicle_bn254.BaseField
		base.FromLimbs(s)
		field = T(base)
	case icicle_bn254.ScalarField:
		var scalar icicle_bn254.ScalarField
		scalar.FromLimbs(s)
		field = T(scalar)
	}
	return &field
}

func NewFieldFromFpGnark[T icicle_bn254.BaseField | icicle_bn254.ScalarField](element fp.Element) *T {
	element_bits := element.Bits()
	s := core.ConvertUint64ArrToUint32Arr(element_bits[:]) // get non-montgomry

	var field T
	switch any(field).(type) {
	case icicle_bn254.BaseField:
		var base icicle_bn254.BaseField
		base.FromLimbs(s)
		field = T(base)
	case icicle_bn254.ScalarField:
		var scalar icicle_bn254.ScalarField
		scalar.FromLimbs(s)
		field = T(scalar)
	}
	return &field
}

func BaseFieldToGnarkFr(f *icicle_bn254.BaseField) *fr.Element {
	v, _ := fr.LittleEndian.Element((*[fr.Bytes]byte)(f.ToBytesLittleEndian()))
	return &v
}

func BaseFieldToGnarkFp(f *icicle_bn254.BaseField) *fp.Element {
	v, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(f.ToBytesLittleEndian()))
	return &v
}
