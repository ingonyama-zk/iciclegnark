// Copyright 2023 Ingonyama
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bls12377

import (
	"bufio"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"github.com/stretchr/testify/assert"
)

func randG1Jac() (bls12377.G1Jac, error) {
	var point bls12377.G1Jac
	var scalar fr.Element

	_, err := scalar.SetRandom()
	if err != nil {
		return point, err
	}

	genG1Jac, _, _, _ := bls12377.Generators()

	//randomBigInt, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	//randomBigInt, err := rand.Int(rand.Reader, big.NewInt(100))
	randomBigInt := big.NewInt(100)

	point.ScalarMultiplication(&genG1Jac, scalar.BigInt(randomBigInt))
	return point, nil
}

func GeneratePoints(count int) ([]icicle.G1PointAffine, []bls12377.G1Affine) {
	// Declare a slice of integers
	var points []icicle.G1PointAffine
	var pointsAffine []bls12377.G1Affine

	// populate the slice
	for i := 0; i < 10; i++ {
		gnarkP, _ := randG1Jac()
		var pointAffine bls12377.G1Affine
		pointAffine.FromJacobian(&gnarkP)

		var p icicle.G1ProjectivePoint
		G1ProjectivePointFromJacGnark(&p, &gnarkP)

		pointsAffine = append(pointsAffine, pointAffine)
		points = append(points, *p.StripZ())
	}

	log2_10 := math.Log2(10)
	log2Count := math.Log2(float64(count))
	log2Size := int(math.Ceil(log2Count - log2_10))

	for i := 0; i < log2Size; i++ {
		pointsAffine = append(pointsAffine, pointsAffine...)
		points = append(points, points...)
	}

	return points[:count], pointsAffine[:count]
}

func ReadGnarkPointsFromFile(filePath string, size int) (points []icicle.G1PointAffine, gnarkPoints []bls12377.G1Affine) {
	points = make([]icicle.G1PointAffine, size)
	gnarkPoints = make([]bls12377.G1Affine, size)
	file, _ := os.Open(filePath)
	scanner := bufio.NewScanner(file)

	for i := 0; scanner.Scan(); i++ {
		gnarkPoints[i].X.SetString(scanner.Text())
		scanner.Scan()
		gnarkPoints[i].Y.SetString(scanner.Text())

		var p icicle.G1ProjectivePoint
		FromG1AffineGnark(&gnarkPoints[i], &p)

		points[i] = *p.StripZ()

	}
	return
}

func GeneratePointsProj(count int) ([]icicle.G1ProjectivePoint, []bls12377.G1Jac) {
	// Declare a slice of integers
	var points []icicle.G1ProjectivePoint
	var pointsAffine []bls12377.G1Jac

	// Use a loop to populate the slice
	for i := 0; i < count; i++ {
		gnarkP, _ := randG1Jac()

		var p icicle.G1ProjectivePoint
		G1ProjectivePointFromJacGnark(&p, &gnarkP)

		pointsAffine = append(pointsAffine, gnarkP)
		points = append(points, p)
	}

	return points, pointsAffine
}

func GenerateScalars(count int, skewed bool) ([]icicle.G1ScalarField, []fr.Element) {
	// Declare a slice of integers
	var scalars []icicle.G1ScalarField
	var scalars_fr []fr.Element

	var rand fr.Element
	var zero fr.Element
	zero.SetZero()
	var one fr.Element
	one.SetOne()
	var randLarge fr.Element
	randLarge.SetRandom()

	if skewed && count > 1_200_000 {
		for i := 0; i < count-1_200_000; i++ {
			rand.SetRandom()
			s := NewFieldFromFrGnark[icicle.G1ScalarField](rand)

			scalars_fr = append(scalars_fr, rand)
			scalars = append(scalars, *s)
		}

		for i := 0; i < 600_000; i++ {
			s := NewFieldFromFrGnark[icicle.G1ScalarField](randLarge)

			scalars_fr = append(scalars_fr, randLarge)
			scalars = append(scalars, *s)
		}
		for i := 0; i < 400_000; i++ {
			s := NewFieldFromFrGnark[icicle.G1ScalarField](zero)

			scalars_fr = append(scalars_fr, zero)
			scalars = append(scalars, *s)
		}
		for i := 0; i < 200_000; i++ {
			s := NewFieldFromFrGnark[icicle.G1ScalarField](one)

			scalars_fr = append(scalars_fr, one)
			scalars = append(scalars, *s)
		}
	} else {
		for i := 0; i < count; i++ {
			rand.SetRandom()
			s := NewFieldFromFrGnark[icicle.G1ScalarField](rand)

			scalars_fr = append(scalars_fr, rand)
			scalars = append(scalars, *s)
		}
	}

	return scalars[:count], scalars_fr[:count]
}

func ReadGnarkScalarsFromFile(filePath string, size int) (scalars []icicle.G1ScalarField, gnarkScalars []fr.Element) {
	scalars = make([]icicle.G1ScalarField, size)
	gnarkScalars = make([]fr.Element, size)
	file, _ := os.Open(filePath)
	scanner := bufio.NewScanner(file)
	for i := 0; scanner.Scan(); i++ {
		gnarkScalars[i].SetString(scanner.Text())
		scalars[i] = *NewFieldFromFrGnark[icicle.G1ScalarField](gnarkScalars[i])
	}
	return
}

func TestMSM(t *testing.T) {
	for _, v := range []int{24} {
		count := 1 << v

		points, gnarkPoints := GeneratePoints(count)
		fmt.Print("Finished generating points\n")
		scalars, gnarkScalars := GenerateScalars(count, true)
		fmt.Print("Finished generating scalars\n")

		out := new(icicle.G1ProjectivePoint)
		startTime := time.Now()
		_, e := icicle.Msm(out, points, scalars, 0) // non mont
		fmt.Printf("icicle MSM took: %d ms\n", time.Since(startTime).Milliseconds())

		assert.Equal(t, e, nil, "error should be nil")
		fmt.Print("Finished icicle MSM\n")

		var bls12377AffineLib bls12377.G1Affine

		gResult, _ := bls12377AffineLib.MultiExp(gnarkPoints, gnarkScalars, ecc.MultiExpConfig{})
		fmt.Print("Finished Gnark MSM\n")

		assert.True(t, gResult.Equal(ProjectiveToGnarkAffine(out)))
	}
}

func TestCommitMSM(t *testing.T) {
	for _, v := range []int{24} {
		count := 1<<v - 1
		// count := 12_180_757

		points, gnarkPoints := GeneratePoints(count)
		fmt.Print("Finished generating points\n")
		scalars, gnarkScalars := GenerateScalars(count, true)
		fmt.Print("Finished generating scalars\n")

		out_d, _ := goicicle.CudaMalloc(96)

		pointsBytes := count * 64
		points_d, _ := goicicle.CudaMalloc(pointsBytes)
		goicicle.CudaMemCpyHtoD[icicle.G1PointAffine](points_d, points, pointsBytes)

		scalarBytes := count * 32
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		goicicle.CudaMemCpyHtoD[icicle.G1ScalarField](scalars_d, scalars, scalarBytes)

		startTime := time.Now()
		e := icicle.Commit(out_d, scalars_d, points_d, count, 10)
		fmt.Printf("icicle MSM took: %d ms\n", time.Since(startTime).Milliseconds())

		outHost := make([]icicle.G1ProjectivePoint, 1)
		goicicle.CudaMemCpyDtoH[icicle.G1ProjectivePoint](outHost, out_d, 96)

		assert.Equal(t, e, 0, "error should be 0")
		fmt.Print("Finished icicle MSM\n")

		fmt.Println("Res on curve: ", G1ProjectivePointToGnarkJac(&outHost[0]).IsOnCurve())

		var bls12377AffineLib bls12377.G1Affine

		gResult, _ := bls12377AffineLib.MultiExp(gnarkPoints, gnarkScalars, ecc.MultiExpConfig{})
		fmt.Print("Finished Gnark MSM\n")

		assert.True(t, gResult.Equal(ProjectiveToGnarkAffine(&outHost[0])))
	}
}

func BenchmarkCommit(b *testing.B) {
	LOG_MSM_SIZES := []int{20, 21, 22, 23, 24, 25, 26}

	for _, logMsmSize := range LOG_MSM_SIZES {
		msmSize := 1 << logMsmSize
		points, _ := GeneratePoints(msmSize)
		scalars, _ := GenerateScalars(msmSize, false)

		out_d, _ := goicicle.CudaMalloc(96)

		pointsBytes := msmSize * 64
		points_d, _ := goicicle.CudaMalloc(pointsBytes)
		goicicle.CudaMemCpyHtoD[icicle.G1PointAffine](points_d, points, pointsBytes)

		scalarBytes := msmSize * 32
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		goicicle.CudaMemCpyHtoD[icicle.G1ScalarField](scalars_d, scalars, scalarBytes)

		b.Run(fmt.Sprintf("MSM %d", logMsmSize), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				e := icicle.Commit(out_d, scalars_d, points_d, msmSize, 10)

				if e != 0 {
					panic("Error occured")
				}
			}
		})
	}
}

func TestBenchMSM(t *testing.T) {
	for _, batchPow2 := range []int{2, 4} {
		for _, pow2 := range []int{4, 6} {
			msmSize := 1 << pow2
			batchSize := 1 << batchPow2
			count := msmSize * batchSize

			points, _ := GeneratePoints(count)
			scalars, _ := GenerateScalars(count, false)

			a, e := icicle.MsmBatch(&points, &scalars, batchSize, 0)

			if e != nil {
				t.Errorf("MsmBatchbls12377 returned an error: %v", e)
			}

			if len(a) != batchSize {
				t.Errorf("Expected length %d, but got %d", batchSize, len(a))
			}
		}
	}
}

func BenchmarkMSM(b *testing.B) {
	LOG_MSM_SIZES := []int{20, 21, 22, 23, 24, 25, 26}

	for _, logMsmSize := range LOG_MSM_SIZES {
		msmSize := 1 << logMsmSize
		points, _ := GeneratePoints(msmSize)
		scalars, _ := GenerateScalars(msmSize, false)
		b.Run(fmt.Sprintf("MSM %d", logMsmSize), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				out := new(icicle.G1ProjectivePoint)
				_, e := icicle.Msm(out, points, scalars, 0)

				if e != nil {
					panic("Error occured")
				}
			}
		})
	}
}

// G2

func randG2Jac() (bls12377.G2Jac, error) {
	var point bls12377.G2Jac
	var scalar fr.Element

	_, err := scalar.SetRandom()
	if err != nil {
		return point, err
	}

	_, genG2Jac, _, _ := bls12377.Generators()

	randomBigInt := big.NewInt(1000)

	point.ScalarMultiplication(&genG2Jac, scalar.BigInt(randomBigInt))
	return point, nil
}

func GenerateG2Points(count int) ([]icicle.G2PointAffine, []bls12377.G2Affine) {
	// Declare a slice of integers
	var points []icicle.G2PointAffine
	var pointsAffine []bls12377.G2Affine

	// populate the slice
	for i := 0; i < 10; i++ {
		gnarkP, _ := randG2Jac()

		var p icicle.G2PointAffine
		G2PointAffineFromGnarkJac(&gnarkP, &p)

		var gp bls12377.G2Affine
		gp.FromJacobian(&gnarkP)
		pointsAffine = append(pointsAffine, gp)
		points = append(points, p)
	}

	log2_10 := math.Log2(10)
	log2Count := math.Log2(float64(count))
	log2Size := int(math.Ceil(log2Count - log2_10))

	for i := 0; i < log2Size; i++ {
		pointsAffine = append(pointsAffine, pointsAffine...)
		points = append(points, points...)
	}

	return points[:count], pointsAffine[:count]
}

func ReadGnarkG2PointsFromFile(filePath string, size int) (points []icicle.G2PointAffine, gnarkPoints []bls12377.G2Affine) {
	points = make([]icicle.G2PointAffine, size)
	gnarkPoints = make([]bls12377.G2Affine, size)
	file, _ := os.Open(filePath)
	scanner := bufio.NewScanner(file)
	for i := 0; scanner.Scan(); i++ {
		x := scanner.Text()
		xSplits := strings.Split(x, "+")
		xA0 := xSplits[0]
		xA1Splits := strings.Split(xSplits[1], "*")
		xA1 := xA1Splits[0]
		gnarkPoints[i].X.SetString(xA0, xA1)

		scanner.Scan()
		y := scanner.Text()
		ySplits := strings.Split(y, "+")
		yA0 := ySplits[0]
		yA1Splits := strings.Split(ySplits[1], "*")
		yA1 := yA1Splits[0]
		gnarkPoints[i].Y.SetString(yA0, yA1)

		G2AffineFromGnarkAffine(&gnarkPoints[i], &points[i])
	}
	return
}

func TestMsmG2bls12377(t *testing.T) {
	for _, v := range []int{24} {
		count := 1 << v
		points, gnarkPoints := GenerateG2Points(count)
		fmt.Print("Finished generating points\n")
		scalars, gnarkScalars := GenerateScalars(count, false)
		fmt.Print("Finished generating scalars\n")

		out := new(icicle.G2Point)
		_, e := icicle.MsmG2(out, points, scalars, 0)
		assert.Equal(t, e, nil, "error should be nil")

		var result icicle.G2PointAffine
		var bls12377AffineLib bls12377.G2Affine

		gResult, _ := bls12377AffineLib.MultiExp(gnarkPoints, gnarkScalars, ecc.MultiExpConfig{})

		G2AffineFromGnarkAffine(gResult, &result)

		pp := result.ToProjective()
		assert.True(t, out.Eq(&pp))
	}
}

func BenchmarkMsmG2bls12377(b *testing.B) {
	LOG_MSM_SIZES := []int{20, 21, 22, 23, 24, 25, 26}

	for _, logMsmSize := range LOG_MSM_SIZES {
		msmSize := 1 << logMsmSize
		points, _ := GenerateG2Points(msmSize)
		scalars, _ := GenerateScalars(msmSize, false)
		b.Run(fmt.Sprintf("MSM G2 %d", logMsmSize), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				out := new(icicle.G2Point)
				_, e := icicle.MsmG2(out, points, scalars, 0)

				if e != nil {
					panic("Error occured")
				}
			}
		})
	}
}

func TestCommitG2MSM(t *testing.T) {
	for _, v := range []int{24} {
		count := 1 << v

		points, gnarkPoints := GenerateG2Points(count)
		fmt.Print("Finished generating points\n")
		scalars, gnarkScalars := GenerateScalars(count, true)
		fmt.Print("Finished generating scalars\n")

		var sizeCheckG2PointAffine icicle.G2PointAffine
		inputPointsBytes := count * int(unsafe.Sizeof(sizeCheckG2PointAffine))

		var sizeCheckG2Point icicle.G2Point
		out_d, _ := goicicle.CudaMalloc(int(unsafe.Sizeof(sizeCheckG2Point)))

		points_d, _ := goicicle.CudaMalloc(inputPointsBytes)
		goicicle.CudaMemCpyHtoD[icicle.G2PointAffine](points_d, points, inputPointsBytes)

		scalarBytes := count * 32
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		goicicle.CudaMemCpyHtoD[icicle.G1ScalarField](scalars_d, scalars, scalarBytes)

		startTime := time.Now()
		e := icicle.CommitG2(out_d, scalars_d, points_d, count, 10)
		fmt.Printf("icicle MSM took: %d ms\n", time.Since(startTime).Milliseconds())

		outHost := make([]icicle.G2Point, 1)
		goicicle.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, int(unsafe.Sizeof(sizeCheckG2Point)))

		assert.Equal(t, e, 0, "error should be 0")
		fmt.Print("Finished icicle MSM\n")

		var bls12377AffineLib bls12377.G2Affine

		gResult, _ := bls12377AffineLib.MultiExp(gnarkPoints, gnarkScalars, ecc.MultiExpConfig{})
		fmt.Print("Finished Gnark MSM\n")
		var resultGnark icicle.G2PointAffine
		G2AffineFromGnarkAffine(gResult, &resultGnark)

		resultGnarkProjective := resultGnark.ToProjective()
		assert.Equal(t, len(outHost), 1)
		result := outHost[0]

		assert.True(t, result.Eq(&resultGnarkProjective))
	}
}

func TestBatchG2MSM(t *testing.T) {
	for _, batchPow2 := range []int{2, 4} {
		for _, pow2 := range []int{4, 6} {
			msmSize := 1 << pow2
			batchSize := 1 << batchPow2
			count := msmSize * batchSize

			points, _ := GenerateG2Points(count)
			scalars, _ := GenerateScalars(count, false)

			a, e := icicle.MsmG2Batch(&points, &scalars, batchSize, 0)

			if e != nil {
				t.Errorf("MsmBatchbls12377 returned an error: %v", e)
			}

			if len(a) != batchSize {
				t.Errorf("Expected length %d, but got %d", batchSize, len(a))
			}
		}
	}
}
