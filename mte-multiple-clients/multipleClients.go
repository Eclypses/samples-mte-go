/*****************************************************************************
THIS SOFTWARE MAY NOT BE USED FOR PRODUCTION. Otherwise,
The MIT License (MIT)

Copyright (c) Eclypses, Inc.

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crRand "crypto/rand"
	"eclypsesEcdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"multipleClients/mte"

	"github.com/coocood/freecache"
	"github.com/google/uuid"
)

const (
	//--------------------
	// Content type const
	jsonContent    = "application/json"
	textContent    = "text/plain"
	clientIdHeader = "x-client-id"
	encPrefix      = "enc_"
	decPrefix      = "dec_"
	cacheExpire    = 0
	maxNumTrips    = 20

	//---------------------------
	// Connection and Route urls
	restAPIName = "https://dev-echo.eclypses.com" // Public Echo API
	//restAPIName = "http://localhost:52603" // Local MteDemo API
	handshakeRoute   = "/api/handshake"
	multiClientRoute = "/api/multiclient"
	reseedPercent    = .9

	//-------------------------
	// MTE license information
	companyName    = ""
	companyLicense = ""
	useMte         = true

	//--------------------------
	// Error return exit codes
	errorPerformingHandshake     = 101
	errorMarshalJson             = 102
	errorHttpPost                = 103
	errorReadingResponse         = 104
	errorHttpGet                 = 105
	errorInvalidConnectionMethod = 106
	errorFromServer              = 107
	errorCreatingEncoder         = 111
	errorCreatingDecoder         = 112
	errorBase64Decoding          = 113
	errorDecodingData            = 114
	errorValidation              = 115
	errorRetrievingState         = 116
	errorDecryptingState         = 117
	errorRestoringState          = 118
	errorEncodingData            = 119
	errorEncryptingState         = 120
	errorCreatingPK              = 121
	errorCreatingSS              = 122
	errorDecodingPK              = 123
	errorMteLicense              = 124
	errorParsingUint             = 125
	errorNewCipher               = 126
	errorNewGCM                  = 127
	endProgram                   = 130
)

type HandshakeModel struct {
	TimeStamp              string
	ConversationIdentifier string
	ClientEncoderPublicKey string
	ClientDecoderPublicKey string
}

type ResponseModel[T any] struct {
	Message      string
	Success      bool
	ResultCode   string
	ExceptionUid string
	Data         T
}

//------------
// Return code
var retcode int
var maxSeed uint64

//---------------------------
// Container for client Id's
var clients map[int]string

//--------------------------
// Aes GCM cipher container
var gcm cipher.AEAD

//------------------------
// FreeCache container
var stateCache = freecache.NewCache(512 * 1024 * 1024)

/**
 * Main function kicks off the handshake then multiple clients
 */
func main() {

	//----------------------------------------------------
	// Defer the exit so all other defer calls are called
	retcode = 0
	defer func() { os.Exit(retcode) }()
	//---------------------
	// Generate AES Cipher
	err := GenerateAesCipher()
	if err != nil {
		fmt.Println(err)
		return
	}

	var numClients int
	//-----------------------------
	// Prompt for number of clients
	fmt.Print("How many clients? (Enter number between 1-50)\n")

	_, err = fmt.Scanf("%d", &numClients)
	if err != nil {
		fmt.Println(err)
		retcode = errorValidation
		return
	}
	//------------------------
	// Initialize client list
	clients = make(map[int]string)

	//-----------------------------------------
	// Run handshake and state for each client
	//-----------------------------------------
	for i := 1; i <= numClients; i++ {
		//--------------------
		// Initialize client
		clientId := uuid.New().String()

		//------------------------------------
		// Add this client to our clients map
		clients[i] = clientId

		//------------------------------------
		// Perform handshake for this client
		retcode, err := PerformHandshakeWithServer(i, clientId)
		if err != nil {
			fmt.Println("Error: " + err.Error() + " Code: " + strconv.Itoa(retcode))
			return
		}
	}

	//------------------------------
	// Loop till user chooses to end
	for {
		//------------------------------------------------
		// Create the waitgroup so we can run these async
		var wg sync.WaitGroup
		wg.Add(numClients)

		//-----------------------------------------
		// Send message to server for each client
		for i := 1; i <= numClients; i++ {
			go SendMultiToServer(clients[i], i, &wg)
		}
		//----------------------------------
		// Wait till all tasks are complete
		wg.Wait()

		//-----------------------------------------
		// Prompt user if they want to run it again
		fmt.Print("\nWould you like to send client message again (y/n)?\n")
		qReader := bufio.NewReader(os.Stdin)

		sendAgain, _ := qReader.ReadString('\n')
		//---------------------------
		// Take off carriage return
		sendAgain = strings.Replace(sendAgain, "\n", "", -1)
		sendAgain = strings.Replace(sendAgain, "\r", "", -1)

		//----------------------
		// Check user response
		if strings.ToLower(sendAgain) == "n" {
			fmt.Println("Program stopped.")
			retcode = endProgram
			return
		}
	}
}

/**
 * Send MTE Encoded message to server
 */
func SendMultiToServer(clientId string, clientNum int, wg *sync.WaitGroup) {

	//-------------------------------------------------
	// Make sure done is called when this if finsihed
	defer wg.Done()
	//--------------------------------------------
	// Get random number of times to send messages
	randNum := mrand.Intn(maxNumTrips-1) + 1
	//-----------------
	// Create Encoder
	encoder := mte.NewEncDef()
	defer encoder.Destroy()
	//--------------------------------------------------
	// Get the Encoder state from the cache and decrypt
	encoderState, err := stateCache.Get([]byte(encPrefix + clientId))
	nonceSize := gcm.NonceSize()
	if len(encoderState) < nonceSize {
		fmt.Println(err)
		retcode = errorRetrievingState
		return
	}

	aesNonce, encoderState := encoderState[:nonceSize], encoderState[nonceSize:]
	decryptedState, err := gcm.Open(nil, aesNonce, encoderState, nil)
	if err != nil {
		fmt.Println(err)
		retcode = errorDecryptingState
		return
	}
	//---------------------------
	// Restore the Encoder state
	encoderStatus := encoder.RestoreState(decryptedState)
	if encoderStatus != mte.Status_mte_status_success {
		errorMessage := "Encoder restore error (" + mte.GetStatusName(encoderStatus) + ", " + mte.GetStatusDescription(encoderStatus) + ")"
		fmt.Println(errorMessage)
		retcode = errorRestoringState
		return
	}
	//------------------------
	// Create the MTE Decoder
	decoder := mte.NewDecDef()
	defer decoder.Destroy()
	//-----------------------------------
	// Get the Decoder state and decrypt
	decoderState, err := stateCache.Get([]byte(decPrefix + clientId))
	nonceSize = gcm.NonceSize()
	if len(decoderState) < nonceSize {
		fmt.Println(err)
		retcode = errorRetrievingState
		return
	}

	aesNonce, decoderState = decoderState[:nonceSize], decoderState[nonceSize:]
	decryptedState, err = gcm.Open(nil, aesNonce, decoderState, nil)
	if err != nil {
		fmt.Println(err)
		retcode = errorDecryptingState
		return
	}
	//---------------------------
	// Restore the Decoder state
	decoderStatus := decoder.RestoreState(decryptedState)
	if decoderStatus != mte.Status_mte_status_success {
		errorMessage := "Decoder restore error (" + mte.GetStatusName(decoderStatus) + ", " + mte.GetStatusDescription(decoderStatus) + ")"
		fmt.Println(errorMessage)
		retcode = errorRestoringState
		return
	}
	//---------------------------------------------------------------
	// Send message to server random number of times for this client
	for i := 1; i <= randNum; i++ {
		//----------------------
		// Set message content
		message := "Hello from client " + strconv.Itoa(clientNum) + " : " + clientId + " for the " + strconv.Itoa(i) + " time"
		//----------------
		// Encode message
		encoded, encoderStatus := encoder.EncodeStrB64(message)
		if encoderStatus != mte.Status_mte_status_success {
			errorMessage := "Encode error " + mte.GetStatusName(encoderStatus) + " , " + mte.GetStatusDescription(encoderStatus)
			fmt.Println(errorMessage)
			retcode = errorEncodingData
			return
		}
		//------------------------------------
		// Make Http Call to send to server
		hsModelString, errorcode, err := MakeHttpCall(restAPIName+multiClientRoute, "POST", clientId, textContent, encoded)
		if err != nil {
			errorMessage := "Error making Http call: " + err.Error() + " Code: " + strconv.Itoa(errorcode)
			fmt.Println(errorMessage)
			retcode = errorcode
			return
		}

		//-----------------------------
		// Marshal json back to class
		hrBytes := []byte(hsModelString)
		var serverResponse ResponseModel[string]
		json.Unmarshal(hrBytes, &serverResponse)
		if !serverResponse.Success {
			errorMessage := "Error back from server: " + serverResponse.Message + " Code: " + strconv.Itoa(errorFromServer)
			fmt.Println(errorMessage)
			retcode = errorMarshalJson
			return
		}
		//-----------------------
		// Decode return message
		decodedMessage, decoderStatus := decoder.DecodeStrB64(serverResponse.Data)
		if mte.StatusIsError(decoderStatus) {
			errorMessage := "Decode error " + mte.GetStatusName(decoderStatus) + " , " + mte.GetStatusDescription(decoderStatus)
			fmt.Println(errorMessage)
			retcode = errorDecodingData
			return
		}
		//----------------------------------------
		// Print out message received from server
		fmt.Println("Received '" + decodedMessage + "' from multi-client server.")

		//-------------------------------
		// Check current reseed interval currentSeed float64
		currentSeed := float64(encoder.GetReseedCounter())
		if currentSeed > (float64(maxSeed) * float64(reseedPercent)) {
			// Uninstantiate the Decoder
			encoderStatus := encoder.Uninstantiate()
			if encoderStatus != mte.Status_mte_status_success {
				// Handle Encoder uninstantiate failure
				fmt.Fprintf(os.Stderr, "Encoder uninstantiate error (%v): %v\n",
					mte.GetStatusName(encoderStatus), mte.GetStatusDescription(encoderStatus))
				retcode = int(encoderStatus)
			}

			//------------------------
			// Call Handshake Method
			// This also re-creates Encoder and Decoder
			retcode, err := PerformHandshakeWithServer(i, clientId)
			if err != nil {
				fmt.Println("Error: " + err.Error() + " Code: " + strconv.Itoa(retcode))
			}
		}
	}
	//--------------------
	// Save Encoder state
	encoderState = encoder.SaveState()
	//-------------------------
	// Delete from cache first
	stateCache.Del([]byte(encPrefix + clientId))
	//------------------------------------
	// Encrypt state to put back in cache
	// Creates a new byte array the size of the nonce
	aesNonce = make([]byte, gcm.NonceSize())
	//-----------------------------------------------------
	// Populates our nonce with a cryptographically secure
	// Random sequence
	if _, err = io.ReadFull(crRand.Reader, aesNonce); err != nil {
		fmt.Println(err)
		retcode = errorEncryptingState
		return
	}
	//---------------------------------------
	// Seal/Encrpyt the actual Encoder State
	encryptedState := gcm.Seal(aesNonce, aesNonce, encoderState, nil)
	//-------------------------------------------
	// Update cache with encrypted Encoder State
	stateCache.Set([]byte(encPrefix+clientId), encryptedState, cacheExpire)

	//---------------------
	// Save Decoder state
	decoderState = decoder.SaveState()
	//-------------------------
	// Delete from cache first
	stateCache.Del([]byte(decPrefix + clientId))
	//------------------------------------
	// Encrypt state to put back in cache
	// Creates a new byte array the size of the nonce
	aesNonce = make([]byte, gcm.NonceSize())
	//-----------------------------------------------------
	// Populates our nonce with a cryptographically secure
	// Random sequence
	if _, err = io.ReadFull(crRand.Reader, aesNonce); err != nil {
		fmt.Println(err)
		retcode = errorEncryptingState
		return
	}
	//---------------------------------------
	// Seal/Encrpyt the actual Decoder State
	encryptedState = gcm.Seal(aesNonce, aesNonce, decoderState, nil)
	//-------------------------------------------
	// Update cache with encrypted Encoder State
	stateCache.Set([]byte(decPrefix+clientId), encryptedState, cacheExpire)
}

/**
 * Performs Handshake with Server
 * Creates the ECDH public keys and sends them to server
 * When receives it back generates the shared secret
 * then creates the Encoder and Decoder and saves the states
 *
 * clientId: clientId string
 *
 * Returns HandshakeResponse: encoderSharedSecret, decoderSharedSecret
 *
 */
func PerformHandshakeWithServer(num int, clientId string) (out int, err error) {

	fmt.Println("Performing handshake for client: " + strconv.FormatInt(int64(num), 10) + " ID: " + clientId)

	//--------------------------------------------
	// Set default return and response parameters
	var handshakeModel HandshakeModel
	handshakeModel.ConversationIdentifier = clientId

	//----------------------------------------------
	// Create eclypses ECDH for Encoder and Decoder
	encoderEcdh := eclypsesEcdh.New()
	decoderEcdh := eclypsesEcdh.New()

	//----------------------------
	// Get the Encoder public key
	clientEncoderPKBytes, err := encoderEcdh.GetPublicKey()
	if err != nil {
		fmt.Println("Error creating Encoder public key: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingPK))
		return errorCreatingPK, err
	}
	//----------------------------
	// Get the Decoder public key
	clientDecoderPKBytes, err := decoderEcdh.GetPublicKey()
	if err != nil {
		fmt.Println("Error creating Decoder public key: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingPK))
		return errorCreatingPK, err
	}
	//-----------------------------------------
	// Base64 encode keys so we can send them
	handshakeModel.ClientEncoderPublicKey = base64.StdEncoding.EncodeToString(clientEncoderPKBytes)
	handshakeModel.ClientDecoderPublicKey = base64.StdEncoding.EncodeToString(clientDecoderPKBytes)
	//----------------------------------
	// Json encode our handshake model
	handshakeString, err := json.Marshal(handshakeModel)
	if err != nil {
		fmt.Println("Error marshalling handshakeModel: " + err.Error() + " Code: " + strconv.Itoa(errorMarshalJson))
		return errorMarshalJson, err
	}
	//----------------------------------
	// Make Http and get return string
	hsModelString, errorcode, err := MakeHttpCall(restAPIName+handshakeRoute, "POST", clientId, jsonContent, string(handshakeString))
	if err != nil {
		fmt.Println("Error making Http call: " + err.Error() + " Code: " + strconv.Itoa(errorcode))
		return errorcode, err
	}
	//-----------------------------
	// Marshal json back to class
	hrBytes := []byte(hsModelString)
	var serverResponse ResponseModel[HandshakeModel]
	json.Unmarshal(hrBytes, &serverResponse)
	if !serverResponse.Success {
		fmt.Println("Error back from server: " + serverResponse.Message + " Code: " + strconv.Itoa(errorFromServer))
		return errorFromServer, errors.New(serverResponse.Message)
	}

	//--------------------------------------------
	// Base64 Decode Encoder public key to []byte
	partnerEncoderPublicKeyb64 := make([]byte, base64.StdEncoding.DecodedLen(len(serverResponse.Data.ClientEncoderPublicKey)))
	n, err := base64.StdEncoding.Decode(partnerEncoderPublicKeyb64, []byte(serverResponse.Data.ClientEncoderPublicKey))
	if err != nil {
		fmt.Println("Error base64 decode encoderPK: " + err.Error() + " Code: " + strconv.Itoa(errorDecodingPK))
		return errorDecodingPK, err
	}
	partnerEncoderPublicKeyBytes := partnerEncoderPublicKeyb64[:n]

	//--------------------------------------------
	// Base64 Decode Decoder public key to []byte
	partnerDecoderPublicKeyb64 := make([]byte, base64.StdEncoding.DecodedLen(len(serverResponse.Data.ClientDecoderPublicKey)))
	n, err = base64.StdEncoding.Decode(partnerDecoderPublicKeyb64, []byte(serverResponse.Data.ClientDecoderPublicKey))
	if err != nil {
		fmt.Println("Error base64 decode decoderPK: " + err.Error() + " Code: " + strconv.Itoa(errorDecodingPK))
		return errorDecodingPK, err
	}
	partnerDecoderPublicKeyBytes := partnerDecoderPublicKeyb64[:n]
	//-------------------------------
	// Create Encoder shared secret
	enSSBytes, err := encoderEcdh.CreateSharedSecret(partnerEncoderPublicKeyBytes, nil)
	if err != nil {
		fmt.Println("Error creating Encoder shared secret: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingSS))
		return errorCreatingSS, err
	}

	//-----------------------------
	// Create Decoder shared secret
	deSSBytes, err := decoderEcdh.CreateSharedSecret(partnerDecoderPublicKeyBytes, nil)
	if err != nil {
		fmt.Println("Error creating Decoder shared secret: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingSS))
		return errorCreatingSS, err
	}
	//-------------------------
	// Clear out container
	encoderEcdh.ClearContainer()
	decoderEcdh.ClearContainer()

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
		retcode = errorMteLicense
		return 0, err
	}

	//---------------------------------
	// Create MTE Encoder and Decoder
	retcode, err := CreateMteEncoder(serverResponse.Data.TimeStamp, clientId, enSSBytes)
	if err != nil {
		fmt.Println("Error creating Encoder: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingEncoder))
		return retcode, err
	}
	retcode, err = CreateMteDecoder(serverResponse.Data.TimeStamp, clientId, deSSBytes)
	if err != nil {
		fmt.Println("Error creating Decoder: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingDecoder))
		return retcode, err
	}

	return 0, nil
}

/**
 * Creates the MTE Encoder and saves encrypted version to Cache
 */
func CreateMteEncoder(timestamp string, clientId string, encoderEntropy []byte) (out int, err error) {
	encoder := mte.NewEncDef()
	defer encoder.Destroy()

	//----------------------------
	// Parse nonce from timestamp
	nonce, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		fmt.Println(err.Error())
		retcode = errorParsingUint
		return 0, err
	}

	//--------------------
	// Initialize Encoder
	encoder.SetEntropy(encoderEntropy)
	encoder.SetNonceInt(nonce)
	status := encoder.InstantiateStr(clientId)
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "Encoder instantiate error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		return int(status), errors.New("encoder instantiate error (" + mte.GetStatusName(status) + "):" + mte.GetStatusDescription(status))
	}

	//-------------------------------
	// Get the MTE max seed interval
	if maxSeed <= 0 {
		maxSeed = mte.GetDrbgsReseedInterval(encoder.GetDrbg())
	}
	//----------------------
	// Get the Encoder state
	encoderState := encoder.SaveState()
	//-----------------------------------------------
	// Encrypt the Encoder state
	// Creates a new byte array the size of the nonce
	aesNonce := make([]byte, gcm.NonceSize())
	//-----------------------------------------------------
	// Populates our nonce with a cryptographically secure
	// Random sequence
	if _, err = io.ReadFull(crRand.Reader, aesNonce); err != nil {
		fmt.Println(err)
		retcode = errorEncryptingState
		return 0, err
	}
	//-----------------------------
	// Encrypt/Seal Encoder state
	encryptedState := gcm.Seal(aesNonce, aesNonce, encoderState, nil)
	//------------------------------
	// Set encrypted state to Cache
	stateCache.Set([]byte(encPrefix+clientId), encryptedState, cacheExpire)

	return 0, nil
}

/**
 * Creates the MTE Decoder and saves encrypted version to Cache
 */
func CreateMteDecoder(timestamp string, clientId string, decoderEntropy []byte) (out int, err error) {
	decoder := mte.NewDecDef()
	defer decoder.Destroy()

	//----------------------------
	// Parse nonce from timestamp
	nonce, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		fmt.Println(err.Error())
		retcode = errorParsingUint
		return 0, err
	}

	//--------------------
	// Initialize Decoder
	//--------------------
	decoder.SetEntropy(decoderEntropy)
	decoder.SetNonceInt(nonce)
	status := decoder.InstantiateStr(clientId)
	if status != mte.Status_mte_status_success {
		fmt.Fprintf(os.Stderr, "Decoder instantiate error (%v): %v\n",
			mte.GetStatusName(status), mte.GetStatusDescription(status))
		return int(status), errors.New("decoder instantiate error (" + mte.GetStatusName(status) + "):" + mte.GetStatusDescription(status))
	}
	//-------------------------
	// Get the Decoder state
	decoderState := decoder.SaveState()
	//-------------------------------------------------
	// Encrypt state before saving in cache
	// Creates a new byte array the size of the nonce
	aesNonce := make([]byte, gcm.NonceSize())
	//------------------------------------------------------
	// Populates our nonce with a cryptographically secure
	// Random sequence
	if _, err = io.ReadFull(crRand.Reader, aesNonce); err != nil {
		fmt.Println(err)
		retcode = errorEncryptingState
		return 0, err
	}
	//---------------------------------
	// Encrypt/Seal the Decoder state
	encryptedState := gcm.Seal(aesNonce, aesNonce, decoderState, nil)
	//----------------------------------------------
	// Set the encrypted Decoder state in the cache
	stateCache.Set([]byte(decPrefix+clientId), encryptedState, cacheExpire)
	return 0, nil
}

/**
 * Makes Http Call
 *
 * route: Route to make the Http call
 * connectionMethod: POST OR GET
 * clientId: clientId string
 * contentType: string with content type description
 * payload: post payload string
 *
 * Returns a json string of what server sends back
 *
 */
func MakeHttpCall(route string,
	connectionMethod string,
	clientId string,
	contentType string,
	payload string) (out string, retcode int, err error) {
	//--------------------
	// Set return string
	var returnString string
	//------------------------------------
	// If this is a POST request do this
	if strings.ToUpper(connectionMethod) == "POST" {
		client := &http.Client{}
		bodyReader := bytes.NewReader([]byte(payload))
		req, _ := http.NewRequest("POST", route, bodyReader)
		//----------------------------------------
		// Set client ID header and content-type
		req.Header.Set(clientIdHeader, clientId)
		req.Header.Set("Content-Type", contentType)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err.Error())
			retcode = errorReadingResponse
			return "", errorReadingResponse, err
		}
		defer resp.Body.Close()
		//-----------------------
		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err.Error())
			return "", errorReadingResponse, err
		}
		//--------------------------------
		// Convert the body to type string
		returnString = string(body)
		//------------------------------------
		// If this is a GET request do this
	} else if strings.ToUpper(connectionMethod) == "GET" {
		resp, err := http.Get(route)
		if err != nil {
			fmt.Println(err.Error())
			return "", errorHttpGet, err
		}
		//------------------------
		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err.Error())
			return "", errorReadingResponse, err
		}
		//--------------------------------
		// Convert the body to type string
		returnString = string(body)
	} else {
		fmt.Println("Invalid connection request")
		return "", errorInvalidConnectionMethod, errors.New("invalid connection request")
	}
	return returnString, 0, nil
}

/**
 * Generate random string for AES key
 */
var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-"

func shortID(length int) string {
	ll := len(chars)
	b := make([]byte, length)
	mrand.Read(b) // generates len(b) random bytes
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}

/**
 * Generate the AES Cipher container
 */
func GenerateAesCipher() error {

	//--------------------------------
	// Generate random string for key
	aesKey := []byte(shortID(32))
	//-------------------------------------------------------
	// Generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Println(err)
		retcode = errorNewCipher
		return err
	}
	//----------------
	// Generate GCM
	gcm, err = cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
		retcode = errorNewGCM
		return err
	}
	return nil
}
