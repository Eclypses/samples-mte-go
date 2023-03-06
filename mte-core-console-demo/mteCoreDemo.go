package main

import (
	"bufio"
	"fmt"
	"goDemo/mte"
	"os"
	"strings"
)

// Application constants
const (
	nonce                 = 0
	personalizationString = "demo"
	companyName           = ""
	companyLicense        = ""
)

func main() {
	//-----------------------------------------------------
	// defer the exit so all other defer calls are called
	//-----------------------------------------------------
	retcode := 0
	defer func() { os.Exit(retcode) }()
	//-----------------------------------------
	// Display the version of MTE we are using
	// (optional) For demo purposes ONLY
	//-----------------------------------------
	mteVersion := mte.GetVersion()
	fmt.Printf("Using Mte Version %s\n", mteVersion)
	//----------------------------
	// Initialize the MTE license
	//----------------------------
	if !mte.InitLicense(companyName, companyLicense) {
		fmt.Println("MTE license appears to be invalid. MTE cannot be initalized.")
		retcode = int(mte.Status_mte_status_license_error)
		return
	}
	//--------------------------
	// create the MTE Encoder
	//--------------------------
	mteEncoder := mte.NewEncDef()
	defer mteEncoder.Destroy()
	//-------------------------------------------------------------------------
	// Create all-zero entropy for this demo. The nonce will also be set to 0.
	// This should never be done in real applications.
	//-------------------------------------------------------------------------
	entropyBytes := mte.GetDrbgsEntropyMinBytes(mteEncoder.GetDrbg())
	entropy := make([]byte, entropyBytes)
	// Fill with 0's
	for i := 0; i < entropyBytes; i++ {
		entropy[i] = '0'
	}
	//--------------------------
	// Set entropy and nonce
	//--------------------------
	mteEncoder.SetEntropy(entropy)
	mteEncoder.SetNonceInt(nonce)
	//--------------------------
	// Instantiate the encoder.
	//--------------------------
	encoderStatus := mteEncoder.InstantiateStr(personalizationString)
	if encoderStatus != mte.Status_mte_status_success {
		// Handle an error here -- below is a sample
		fmt.Fprintf(os.Stderr, "Encoder instantiate error (%v): %v\n",
			mte.GetStatusName(encoderStatus), mte.GetStatusDescription(encoderStatus))
		retcode = int(encoderStatus)
		return
	}
	//-------------------------
	// create the MTE decoder
	//-------------------------
	mteDecoder := mte.NewDecDef()
	defer mteDecoder.Destroy()
	//----------------------------------------------------------------------------
	// Since the entropy is zero'ized so fill again
	// Providing Entropy in this fashion is insecure. This is for demonstration
	// purposes only and should never be done in practice.
	//----------------------------------------------------------------------------
	for i := 0; i < entropyBytes; i++ {
		entropy[i] = '0'
	}
	//---------------------
	// Initialize decoder
	//---------------------
	mteDecoder.SetEntropy(entropy)
	mteDecoder.SetNonceInt(nonce)
	decoderStatus := mteDecoder.InstantiateStr(personalizationString)
	if decoderStatus != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "Decoder instantiate error (%v): %v\n",
			mte.GetStatusName(decoderStatus), mte.GetStatusDescription(decoderStatus))
		retcode = int(decoderStatus)
		return
	}
	//-------------------------------
	// run loop until quit typed in
	//-------------------------------
	for {
		//-----------------------------
		// Prompting message to encode
		//-----------------------------
		fmt.Print("\nPlease enter text to encode: (To end please type 'quit')\n")
		reader := bufio.NewReader(os.Stdin)

		textToEncode, _ := reader.ReadString('\n')
		//---------------------------
		// take off carriage return
		//---------------------------
		textToEncode = strings.Replace(textToEncode, "\n", "", -1)
		textToEncode = strings.Replace(textToEncode, "\r", "", -1)

		if strings.ToLower(textToEncode) == "quit" {
			fmt.Println("Program stopped.")
			retcode = int(100)
			return
		}
		//--------------------------------
		// Encode the string to a string
		//--------------------------------
		encoded, encoderStatus := mteEncoder.EncodeStrB64(textToEncode)
		if encoderStatus != mte.Status_mte_status_success {
			fmt.Fprintf(os.Stderr, "Encode error (%v): %v\n",
				mte.GetStatusName(encoderStatus), mte.GetStatusDescription(encoderStatus))
			retcode = int(encoderStatus)
			return
		}
		//--------------------------------------------------------------------------
		// (optional) convert to base64 to view outgoing mte packet
		// This is for demonstration purposes ONLY and should NOT be done normally
		//--------------------------------------------------------------------------
		fmt.Printf("Base64 encoded representation of the packet being sent: %q\n\n", encoded)

		//--------------------------
		// Decode string to string
		//--------------------------
		decoded, decoderStatus := mteDecoder.DecodeStrB64(encoded)
		if mte.StatusIsError(decoderStatus) {
			fmt.Fprintf(os.Stderr, "Decode error (%v): %v\n",
				mte.GetStatusName(decoderStatus), mte.GetStatusDescription(decoderStatus))
			retcode = int(decoderStatus)
			return
		} else if decoderStatus != mte.Status_mte_status_success {
			fmt.Fprintf(os.Stderr, "Decode warning (%v): %v\n",
				mte.GetStatusName(decoderStatus), mte.GetStatusDescription(decoderStatus))
		}
		//-----------------------------------------
		// If the decoded is blank -- notify user
		// otherwise display decoded message
		//-----------------------------------------
		if len(decoded) == 0 {
			fmt.Print(os.Stderr, "Message was blank\n")
		} else {
			fmt.Printf("Decoded Message: '%s'", decoded)
		}

	}

}
