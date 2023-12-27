package bw6761

import (
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bw6761"
)

func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	devicePtr, _ := goicicle.CudaMalloc(bytes)
	goicicle.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	MontConvOnDevice(devicePtr, len(scalars), false)

	copyDone <- devicePtr
}

func CopyPointsToDevice(points []bw6761.G1Affine, pointsBytes int, copyDone chan unsafe.Pointer) {
	if pointsBytes == 0 {
		copyDone <- nil
	} else {
		devicePtr, _ := goicicle.CudaMalloc(pointsBytes)
		iciclePoints := BatchConvertFromG1Affine(points)
		goicicle.CudaMemCpyHtoD[icicle.G1PointAffine](devicePtr, iciclePoints, pointsBytes)

		copyDone <- devicePtr
	}
}

func CopyG2PointsToDevice(points []bw6761.G2Affine, pointsBytes int, copyDone chan unsafe.Pointer) {
	if pointsBytes == 0 {
		copyDone <- nil
	} else {
		devicePtr, _ := goicicle.CudaMalloc(pointsBytes)
		iciclePoints := BatchConvertFromG2Affine(points)
		goicicle.CudaMemCpyHtoD[icicle.G2PointAffine](devicePtr, iciclePoints, pointsBytes)

		copyDone <- devicePtr
	}
}

func FreeDevicePointer(ptr unsafe.Pointer) {
	goicicle.CudaFree(ptr)
}

func ScalarToGnarkFr(f *icicle.G1ScalarField) *fr.Element {
	fb := f.ToBytesLe()
	var b48 [48]byte
	copy(b48[:], fb[:48])

	v, e := fr.LittleEndian.Element(&b48)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func ScalarToGnarkFp(f *icicle.G1ScalarField) *fp.Element {
	fb := f.ToBytesLe()
	var b96 [96]byte
	copy(b96[:], fb[:96])

	v, e := fp.LittleEndian.Element(&b96)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
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

func NewFieldFromFrGnark(element fr.Element) *icicle.G1ScalarField {
	S := ConvertUint64ArrToUint32Arr6(element.Bits()) // get non-montgomry

	return &icicle.G1ScalarField{S}
}

func NewFieldFromFpGnark(element fp.Element) *icicle.G1BaseField {
	S := ConvertUint64ArrToUint32Arr12(element.Bits()) // get non-montgomry

	return &icicle.G1BaseField{S}
}

func BaseFieldToGnarkFr(f *icicle.G1BaseField) *fr.Element {
	fb := f.ToBytesLe()
	var b48 [48]byte
	copy(b48[:], fb[:48])

	v, e := fr.LittleEndian.Element(&b48)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v got error %v", f, e))
	}

	return &v
}

func BaseFieldToGnarkFp(f *icicle.G1BaseField) *fp.Element {
	fb := f.ToBytesLe()
	var b32 [96]byte
	copy(b32[:], fb[:96])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v got error %v", f, e))
	}

	return &v
}
