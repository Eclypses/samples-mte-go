// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"goJail/mte"
)

type JailRetain struct {
	// Base.
	*mte.Jail

	// Mutated nonce.
	mutated []byte
}

// Decoder options.
const (
	drbg      = mte.Drbgs_mte_drbgs_hash_sha1
	tokBytes  = 2
	verifiers = mte.Verifiers_mte_verifiers_none
	tWindow   = uint64(0)
	sWindow   = 0
)

// Default options.
const (
	defaultPersonal = "user1"
	defaultEntropy  = "0123456789abcdef"
	defaultNonce    = uint64(1234)
)

func doMain() int {
	// Stdin scanner.
	scanner := bufio.NewScanner(os.Stdin)

	// Print the version.
	fmt.Printf("MTE Version: %v\n", mte.GetVersion())

	// Prompt for personalization.
	fmt.Print("Personalization (return for default)> ")
	scanner.Scan()
	personal := scanner.Text()
	if len(personal) == 0 {
		personal = defaultPersonal
	}

	// Prompt for entropy.
	fmt.Print("Entropy (return for default)> ")
	scanner.Scan()
	entropy := scanner.Text()
	if len(entropy) == 0 {
		entropy = defaultEntropy
	}

	// Prompt for nonce.
	nonce := defaultNonce
	fmt.Print("Nonce (return for default)> ")
	scanner.Scan()
	line := scanner.Text()
	if len(line) != 0 {
		nonce, _ = strconv.ParseUint(line, 10, 64)
	}

	// Display settings.
	fmt.Print("\n")
	fmt.Printf("Personal: %v\n", personal)
	fmt.Printf("Entropy:  %v\n", entropy)
	fmt.Printf("Nonce:    %v\n", nonce)
	fmt.Print("\n")

	// Prompt for the device type.
	for i := mte.JailAlgoNone + 1; i < mte.NumJailAlgo; i++ {
		fmt.Printf("%v. %v\n", i, mte.JailAlgos[i])
	}
	fmt.Print("Device type> ")
	scanner.Scan()
	line = scanner.Text()
	device, _ := strconv.ParseUint(line, 10, 32)

	var selection string
	timesToRun := 2
	for i := 0; i < timesToRun; i++ {

		// This is a sample ONLY -- encoder should be done on mobile device
		// This encoder is here to make sample work -- encoder DOES NOT use jailbreak
		// this will fail the second time around like encoder device has been jail broken
		// Create the encoder
		encoder := mte.NewEncOpt(drbg, tokBytes, verifiers)
		defer encoder.Destroy()

		// Create the decoder.
		decoder := mte.NewDecOpt(drbg, tokBytes, verifiers, tWindow, sWindow)
		defer decoder.Destroy()

		var jailAlgo mte.JailAlgo
		if i == 0 {
			jailAlgo = mte.JailAlgo(mte.JailAlgoNone)
			fmt.Println("Using no JailBreak Algo")
		} else {
			jailAlgo = mte.JailAlgo(device)
			fmt.Println("Using JailBreak Algo")
		}

		// Set the device type and nonce seed.
		// first time use NONE for jailbreak to ensure working
		// second time Use the jailbreak nonce callback.
		cb := NewJailRetain()
		cb.SetAlgo(jailAlgo)
		cb.SetNonceSeed(nonce)
		decoder.SetNonceCallback(cb)

		// encoder should be done on device side
		encoder.SetNonceInt(nonce)

		// Set the entropy. Instantiate.
		entropy8 := []byte(entropy)
		decoder.SetEntropy(entropy8)
		status := decoder.InstantiateStr(personal)
		if status != mte.Status_mte_status_success {
			fmt.Fprintf(os.Stderr, "INSTANTIATE ERROR: %v",
				mte.GetStatusDescription(status))
			return int(status)
		}

		// refill entropy for encoder
		entropyEn := []byte(entropy)
		encoder.SetEntropy(entropyEn)
		encoderStatus := encoder.InstantiateStr(personal)
		if encoderStatus != mte.Status_mte_status_success {
			fmt.Fprintf(os.Stderr, "INSTANTIATE ERROR: %v",
				mte.GetStatusDescription(encoderStatus))
			return int(encoderStatus)
		}

		// Display the mutated nonce.
		fmt.Print("\n")
		mutated := base64.StdEncoding.EncodeToString(cb.GetMutated())
		fmt.Printf("Mutated nonce: %v\n", mutated)

		if selection == "" {
			// Select where to get encoded message from:
			fmt.Println("Please select one: (Will select #2 if input invalid or empty")
			fmt.Println("1. Enter message encoded by device.")
			fmt.Println("2. Enter message to encode.")

			scanner.Scan()
			selection = scanner.Text()
		}

		var textToEncode string
		var encoded string
		if selection == "1" {
			fmt.Println("Please enter encoded text:")
			encoded = scanner.Text()
		} else {
			fmt.Println("Please enter message to encode:")
			scanner.Scan()
			textToEncode = scanner.Text()

			// encode the message
			encoded, encoderStatus = encoder.EncodeStrB64(textToEncode)
			if encoderStatus != mte.Status_mte_status_success {
				fmt.Fprintf(os.Stderr, "Encode error (%v): %v\n",
					mte.GetStatusName(encoderStatus), mte.GetStatusDescription(encoderStatus))
				//retcode = int(encoderStatus)
				return int(encoderStatus)
			}
		}
		fmt.Print("\n")

		// Decode.
		decoded, status := decoder.DecodeStrB64(encoded)
		if status != mte.Status_mte_status_success {
			fmt.Fprintf(os.Stderr, "DECODE ERROR: %v",
				mte.GetStatusDescription(status))
			return int(status)
		}

		// Display the decoded message.
		fmt.Printf("Decoded message: %v\n", decoded)

	}

	// Success.
	return 0
}

func main() {
	os.Exit(doMain())
}

func NewJailRetain() *JailRetain {
	return &JailRetain{Jail: mte.NewJail()}
}

func (jr *JailRetain) GetMutated() []byte {
	return jr.mutated
}

func (jr *JailRetain) NonceCallback(minLength int,
	maxLength int,
	nonce []byte,
	nBytes *int) {
	// Super.
	jr.Jail.NonceCallback(minLength, maxLength, nonce, nBytes)

	// Retain a copy of the mutated nonce.
	jr.mutated = make([]byte, *nBytes)
	copy(jr.mutated, nonce)
}
