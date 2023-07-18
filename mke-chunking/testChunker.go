package main

import (
	"bufio"
	"fmt"
	"goSocket/mte"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//-----------------------
// Application constants
//-----------------------
const (
	bufferSize       = 1024
	defaultExtension = ".txt"
	nonce            = 1
	identifier       = "mySecretIdentifier"

	companyName    = ""
	companyLicense = ""
)

func main() {

	//------------------------------------
	// Prompting message for file to copy
	//------------------------------------
	fmt.Print("Please enter path to file\n")
	reader := bufio.NewReader(os.Stdin)

	fPath, _ := reader.ReadString('\n')
	//---------------------------
	// take off carriage return
	//---------------------------
	fPath = strings.Replace(fPath, "\n", "", -1)
	fPath = strings.Replace(fPath, "\r", "", -1)

	//--------------------------------
	// Check to make sure file exists
	//--------------------------------
	_, err := os.Stat(fPath)
	if err != nil {
		fmt.Printf("Path does not exist! %s", err)
		return
	}

	encodedFileName := "encodedFile"
	decodedFileName := "decodedFile"

	//-----------------------
	// Get the file extension
	//-----------------------
	extension := defaultExtension
	fExt := filepath.Ext(fPath)
	if len(fExt) > 0 {
		extension = fExt
	}

	encodedFileName = encodedFileName + extension
	decodedFileName = decodedFileName + extension

	//---------------
	// Open the file
	//---------------
	f, err := os.Open(fPath)
	if err != nil {
		fmt.Printf("error opening %s: %s", fPath, err)
		return
	}
	defer f.Close()
	//-----------------------------------------
	// Check if file we are creating is there
	// If present delete file
	//-----------------------------------------
	_, err = os.Stat(encodedFileName)
	if err == nil {
		e := os.Remove(encodedFileName)
		if e != nil {
			fmt.Printf("Error trying to delete file %s", encodedFileName)
		}
	}
	//--------------------------------
	// Create MKE Encoder and Decoder
	//--------------------------------
	encoder := mte.NewMkeEncDef()
	defer encoder.Destroy()

	decoder := mte.NewMkeDecDef()
	defer decoder.Destroy()

	//----------------------------------------------------
	// defer the exit so all other defer calls are called
	//----------------------------------------------------
	retcode := 0
	defer func() { os.Exit(retcode) }()
	//------------------------------------
	// Check version and output to screen
	//------------------------------------
	mteVersion := mte.GetVersion()
	fmt.Printf("Using Mte Version %s\n", mteVersion)
	//--------------------------------
	// Check license -- use constants
	// If no license can be blank
	//--------------------------------
	if !mte.InitLicense(companyName, companyLicense) {
		fmt.Println("There was an error attempting to initialize the MTE License.")
		return
	}
	//----------------------------------------------------------------------------
	// check how long entropy we need, set default
	// Providing Entropy in this fashion is insecure. This is for demonstration
	// purposes only and should never be done in practice.
	//----------------------------------------------------------------------------
	entropyBytes := mte.GetDrbgsEntropyMinBytes(encoder.GetDrbg())
	entropy := make([]byte, entropyBytes)
	//---------------
	// Fill with 0's
	//---------------
	for i := 0; i < entropyBytes; i++ {
		entropy[i] = '0'
	}
	//--------------------
	// Initialize encoder
	//--------------------
	encoder.SetEntropy(entropy)
	encoder.SetNonceInt(nonce)
	status := encoder.InstantiateStr(identifier)
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "Encoder instantiate error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		retcode = int(status)
		return
	}
	//---------------------------------------------------------------------------
	// Since entropy is zero'd after using it for the encoder, fill in again
	// Providing Entropy in this fashion is insecure. This is for demonstration
	// purposes only and should never be done in practice.
	//---------------------------------------------------------------------------
	for i := 0; i < entropyBytes; i++ {
		entropy[i] = '0'
	}
	//---------------------
	// Initialize decoder
	//---------------------
	decoder.SetEntropy(entropy)
	decoder.SetNonceInt(nonce)
	status = decoder.InstantiateStr(identifier)
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "Decoder instantiate error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		retcode = int(status)
		return
	}
	//---------------------
	// Initialize Chunking
	//---------------------
	status = encoder.StartEncrypt()
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "MTE Encoder startDecrypt error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		retcode = int(status)
		return
	}
	//-------------------------
	// Create destination file
	//-------------------------
	destination, err := os.Create(encodedFileName)
	if err != nil {
		fmt.Printf("Error trying to create destination file %s, err: %s", encodedFileName, err)
	}
	defer destination.Close()

	//-------------------------------------------------
	// Iterate through file and write to new location
	//-------------------------------------------------
	for {
		//------------------------------
		// Create buffer for file parts
		//------------------------------
		buf := make([]byte, bufferSize)
		amountRead, err := f.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Printf("Error trying to read file %s, err: %s", fPath, err)
		}
		if amountRead == 0 {
			//-----------------------------------------------
			// Reached the end of the file, break out of loop
			//-----------------------------------------------
			break
		}

		//----------------------------------------------------------
		// If the amount that was read is less than the buffer size,
		// take a slice of the original buffer
		//---------------------------------------------------------
		if amountRead < bufferSize {
			buf = buf[:amountRead]
		}

		//-----------------------------------------------------------
		// Encrypt the chunk
		//-----------------------------------------------------------
		status = encoder.EncryptChunk(buf)
		if status != mte.Status_mte_status_success {
			fmt.Fprintf(os.Stderr, "Encode error (%v): %v\n",
				mte.GetStatusName(status), mte.GetStatusDescription(status))
			break
		}
		//----------------------------------------
		// Write the encoded bytes to destination
		//----------------------------------------
		if _, err := destination.Write(buf); err != nil {
			fmt.Printf("Error trying to write to file %s, err: %s", encodedFileName, err)
		}
	}
	//-----------------------------
	// End of the file reached
	// Finish the chunking session
	//-----------------------------
	finishEncode, status := encoder.FinishEncrypt()
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "Encode finish error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
	}
	//-------------------------------------------------
	// If there are bytes to write, write them to file
	//-------------------------------------------------
	if finishEncode != nil {
		if _, err := destination.Write(finishEncode); err != nil {
			fmt.Printf("Error trying to write to file %s, err: %s", encodedFileName, err)
		}
	}

	destination.Close()

	//---------------------------
	// Print out success message
	//---------------------------
	fmt.Printf("Finished creating %s file\n", encodedFileName)

	//---------------------------------------------------
	// now read and decode file into new destination -->
	//---------------------------------------------------
	fRead, err := os.Open(encodedFileName)
	if err != nil {
		fmt.Printf("error opening %s: %s", encodedFileName, err)
		return
	}
	defer fRead.Close()

	//--------------------------------
	// If the file is there delete it
	//--------------------------------
	_, err = os.Stat(decodedFileName)
	if err == nil {
		e := os.Remove(decodedFileName)
		if e != nil {
			fmt.Printf("Error trying to delete file %s", decodedFileName)
		}
	}
	//-------------------------------------
	// Initialize decrypt chunking session
	//-------------------------------------
	status = decoder.StartDecrypt()
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "MTE Decoder startDecrypt error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		retcode = int(status)
		return
	}
	//--------------------------------
	// Create final destination file
	//--------------------------------
	finalDest, err := os.Create(decodedFileName)
	if err != nil {
		fmt.Printf("Error trying to create final destination file %s, err: %s", decodedFileName, err)
	}
	defer finalDest.Close()
	//----------------------------------
	// Create buffer to read bytes into
	//----------------------------------

	//------------------------------------------
	// Iterate through encoded file and decode
	//------------------------------------------
	for {
		//------------------------------
		// Create buffer for file parts
		//------------------------------
		buf := make([]byte, bufferSize)
		amountRead, err := fRead.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Printf("Error trying to read file %s, err: %s", encodedFileName, err)
		}
		//-----------------------------------------------------------
		// If we reached the end of the file finish chunking session
		//-----------------------------------------------------------
		if amountRead == 0 {
			//-----------------------------------------------
			// Reached the end of the file, break out of loop
			//-----------------------------------------------
			break
		}

		//----------------------------------------------------------
		// If the amount that was read is less than the buffer size,
		// take a slice of the original buffer
		//---------------------------------------------------------
		if amountRead < bufferSize {
			buf = buf[:amountRead]
		}

		decoded := decoder.DecryptChunk(buf)
		if decoded == nil {
			fmt.Fprintf(os.Stderr, "Decode error.\n")
			break
		}

		if _, err := finalDest.Write(decoded); err != nil {
			fmt.Printf("Error trying to write to file %s, err: %s", decodedFileName, err)
		}

	}
	finishDecodeChunk, status := decoder.FinishDecrypt()
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "MTE Decoder finishDecrypt error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		retcode = int(status)
		return
	}
	//---------------------------------------------------------
	// if the return bytes are nil -- set to empty byte array
	//---------------------------------------------------------
	if finishDecodeChunk != nil {
		if _, err := finalDest.Write(finishDecodeChunk); err != nil {
			fmt.Printf("Error trying to write to file %s, err: %s", encodedFileName, err)
		}
	}
	//---------------------------
	// Print out success message
	//---------------------------
	fmt.Printf("Finished creating %s file\n", decodedFileName)
}
