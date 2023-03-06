// THIS SOFTWARE MAY NOT BE USED FOR PRODUCTION. Otherwise,
// The MIT License (MIT)
//
// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
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
	"fmt"
	"os"
	"strings"

	"goSeq/mte"
)

func doMain() int {
  // Status.
  var status mte.Status

  // Inputs.
  inputs := [...]string{
    "message 0",
    "message 1",
    "message 2",
    "message 3"}

  // Personalization string.
  const personal = "demo"

  // Initialize MTE license. If a license code is not required (e.g., trial
  // mode), this can be skipped. This demo attempts to load the license info
  // from the environment if required.
  if !mte.InitLicense("YOUR_COMPANY", "YOUR_LICENSE") {
    company := os.Getenv("MTE_COMPANY")
    license := os.Getenv("MTE_LICENSE")
    if len(company) == 0 || len(license) == 0 ||
      !mte.InitLicense(company, license) {
      fmt.Fprintf(os.Stderr, "License init error (%v): %v\n",
        mte.GetStatusName(mte.Status_mte_status_license_error),
        mte.GetStatusDescription(mte.Status_mte_status_license_error))
      return int(mte.Status_mte_status_license_error)
    }
  }

  // Create the encoder.
  encoder := mte.NewEncDef()
  defer encoder.Destroy()

  // Create all-zero entropy for this demo. The nonce will also be set to 0.
  // This should never be done in real applications.
  entropyBytes := mte.GetDrbgsEntropyMinBytes(encoder.GetDrbg())
  entropy := make([]byte, entropyBytes)

  // Instantiate the encoder.
  encoder.SetEntropy(entropy)
  encoder.SetNonceInt(0)
  status = encoder.InstantiateStr(personal)
  if status != mte.Status_mte_status_success {
    fmt.Fprintf(os.Stderr, "Encoder instantiate error (%v): %v\n",
      mte.GetStatusName(status), mte.GetStatusDescription(status))
    return int(status)
  }

  // Encode the inputs.
  var encodings [len(inputs)]string
  for i := 0; i < len(inputs); i++ {
    encodings[i], status = encoder.EncodeStrB64(inputs[i])
    if status != mte.Status_mte_status_success {
      fmt.Fprintf(os.Stderr, "Encode error (%v): %v\n",
        mte.GetStatusName(status), mte.GetStatusDescription(status))
      return int(status)
    }
    fmt.Printf("Encode #%v: %v -> %v\n", i, inputs[i], encodings[i]);
  }

  // Create decoders with different sequence windows.
  decoderV := mte.NewDecWin(0, 0);
  decoderF := mte.NewDecWin(0, 2);
  decoderA := mte.NewDecWin(0, -2);
  defer decoderV.Destroy()
  defer decoderF.Destroy()
  defer decoderA.Destroy()

  // Instantiate the decoders.
  decoderV.SetEntropy(entropy)
  decoderV.SetNonceInt(0)
  status = decoderV.InstantiateStr(personal)
  if status == mte.Status_mte_status_success {
    decoderF.SetEntropy(entropy)
    decoderF.SetNonceInt(0)
    status = decoderF.InstantiateStr(personal)
    if status == mte.Status_mte_status_success {
      decoderA.SetEntropy(entropy)
      decoderA.SetNonceInt(0)
      status = decoderA.InstantiateStr(personal)
    }
  }
  if status != mte.Status_mte_status_success {
    fmt.Fprintf(os.Stderr, "Decoder instantiate error (%v): %v\n",
      mte.GetStatusName(status), mte.GetStatusDescription(status))
    return int(status)
  }

  // Save the async decoder state.
  dsaved := decoderA.SaveState()

  // String to decode to.
  var decoded string

  // Create the corrupt version of message #2.
  first := true
  corrupt := strings.Map(func(r rune) rune {
                           if first {
                             first = false
                             return r + 1
                           }
                           return r
                         }, encodings[2])

  // Decode in verification-only mode.
  fmt.Println("\nVerification-only mode (sequence window = 0):")
  decoded, status = decoderV.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderV.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderV.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderV.DecodeStrB64(encodings[1])
  fmt.Printf("Decode #1: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderV.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderV.DecodeStrB64(encodings[3])
  fmt.Printf("Decode #3: %v, %v\n", mte.GetStatusName(status), decoded)

  // Decode in forward-only mode.
  fmt.Println("\nForward-only mode (sequence window = 2):")
  decoded, status = decoderF.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderF.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderF.DecodeStrB64(corrupt)
  fmt.Printf("Corrupt #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderF.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderF.DecodeStrB64(encodings[1])
  fmt.Printf("Decode #1: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderF.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderF.DecodeStrB64(encodings[3])
  fmt.Printf("Decode #3: %v, %v\n", mte.GetStatusName(status), decoded)

  // Decode in async mode.
  fmt.Println("\nAsync mode (sequence window = -2):")
  decoded, status = decoderA.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(corrupt)
  fmt.Printf("Corrupt #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[1])
  fmt.Printf("Decode #1: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[3])
  fmt.Printf("Decode #3: %v, %v\n", mte.GetStatusName(status), decoded)

  // Restore and decode again in a different order.
  decoderA.RestoreState(dsaved)
  fmt.Println("\nAsync mode (sequence window = -2):")
  decoded, status = decoderA.DecodeStrB64(encodings[3])
  fmt.Printf("Decode #3: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[0])
  fmt.Printf("Decode #0: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[2])
  fmt.Printf("Decode #2: %v, %v\n", mte.GetStatusName(status), decoded)
  decoded, status = decoderA.DecodeStrB64(encodings[1])
  fmt.Printf("Decode #1: %v, %v\n", mte.GetStatusName(status), decoded)

  // Success.
  return 0
}

func main() {
  os.Exit(doMain())
}

