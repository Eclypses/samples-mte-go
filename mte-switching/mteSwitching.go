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
	"eclypsesEcdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"mteSwitching/mte"

	"github.com/google/uuid"
)

//--------------------------------------
// Store the Encoder and Decoder states
var encoderState string
var decoderState string
var maxSeed uint64

//-------------------------------
// Store the authorization token
var access_token string

const (
	//--------------------
	// Content type const
	jsonContent    = "application/json"
	textContent    = "text/plain"
	chunkSize      = 1024
	clientIdHeader = "x-client-id"
	reseedPercent  = .9

	//---------------------------
	// Connection and Route urls
	restAPIName = "https://dev-echo.eclypses.com" // Public Echo API
	// restAPIName          = "http://localhost:52603" // Local MteDemo API
	handshakeRoute       = "/api/handshake"
	fileUploadNoMteRoute = "/FileUpload/nomte?name="
	fileUploadMteRoute   = "/FileUpload/mte?name="
	loginRoute           = "/api/login"

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
	errorDecodingPK              = 108
	errorCreatingPK              = 109
	errorCreatingSS              = 110
	errorCreatingEncoder         = 111
	errorCreatingDecoder         = 112
	errorBase64Decoding          = 113
	errorDecodingData            = 114
	errorPathDoesNotExist        = 115
	endProgram                   = 120
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
	access_token string
	ExceptionUid string
	Data         T
}

type LoginModel struct {
	Password string
	UserName string
}

/**
 * Main function kicks off the ECDH Handshake
 */
func main() {

	//----------------------------------------------------
	// Defer the exit so all other defer calls are called
	retcode := 0
	defer func() { os.Exit(retcode) }()

	//--------------------
	// Initialize client
	clientId := uuid.New().String()

	//------------------------
	// Call Handshake Method
	retcode, err := PerformHandshakeWithServer(clientId)
	if err != nil {
		fmt.Println("Error: " + err.Error() + " Code: " + strconv.Itoa(retcode))
		return
	}

	//---------------------
	// Call Login Method
	// This uses MTE Core
	retcode, err = LoginToServer(clientId)
	if err != nil {
		fmt.Println("Error during login: " + err.Error())
		return
	}

	//-------------------------
	// Call Upload File Method
	// This uses MTE MKE add-on
	retcode, err = UploadFile(clientId)
	if err != nil {
		fmt.Println("Error file upload: " + err.Error())
		return
	}

}

/**
 * Upload file method
 * Allows user to upload files to API
 * Must enter in full path to file
 *
 * Uses MTE MKE Add-on
 */
func UploadFile(clientId string) (out int, err error) {
	//------------------------------
	// Loop till user chooses to end
	for {
		//------------------------------------
		// Prompting message for file to copy
		fmt.Print("Please enter path of file to upload\n")
		reader := bufio.NewReader(os.Stdin)

		fPath, _ := reader.ReadString('\n')
		//---------------------------
		// Take off carriage return
		fPath = strings.Replace(fPath, "\n", "", -1)
		fPath = strings.Replace(fPath, "\r", "", -1)

		//--------------------------------
		// Check to make sure file exists
		_, err = os.Stat(fPath)
		if err != nil {
			fmt.Printf("Path does not exist! %s", err)
			return errorPathDoesNotExist, err
		}
		//---------------------------
		// Create MTE MKE from state
		encoder := mte.NewMkeEncDef()
		defer encoder.Destroy()
		if useMte {
			encoderStatus := encoder.RestoreStateB64(encoderState)
			if encoderStatus != mte.Status_mte_status_success {
				errorMessage := "Encoder restore error (" + mte.GetStatusName(encoderStatus) + "): " + mte.GetStatusDescription(encoderStatus)
				fmt.Println(errorMessage)
				return int(encoderStatus), errors.New(errorMessage)
			}

			//---------------------
			// Initialize Chunking
			encoderStatus = encoder.StartEncrypt()
			if encoderStatus != mte.Status_mte_status_success {
				errorMessage := "MTE Encoder StartEncrypt error (" + mte.GetStatusName(encoderStatus) + "): " + mte.GetStatusDescription(encoderStatus)
				fmt.Println(errorMessage)
				return int(encoderStatus), errors.New(errorMessage)
			}
		}
		//----------------------------
		// Open file and retrieve info
		file, _ := os.Open(fPath)
		fi, _ := file.Stat()
		defer file.Close()
		//----------
		// Set URI
		var route string
		if useMte {
			route = fileUploadMteRoute
		} else {
			route = fileUploadNoMteRoute
		}
		uri := restAPIName + route + fi.Name()
		//-------------------------
		// Calculate content length
		totalSize := fi.Size()
		//------------------------------------------------------------
		// If we are using the MTE add additional length to totalSize
		if useMte {
			totalSize += int64(encoder.EncryptFinishBytes())
		}
		//-------------------------
		// Use pipe to pass request
		rd, wr := io.Pipe()
		defer rd.Close()

		go func() {
			defer wr.Close()
			//-------------
			// Write file
			buf := make([]byte, chunkSize)
			for {
				n, err := file.Read(buf)
				if err != nil {
					if errors.Is(err, io.EOF) {
						if useMte {
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
								if _, err := wr.Write(finishEncode); err != nil {
									fmt.Printf("Error trying to write to file %s, err: %s", fi.Name(), err)
								}
							}
							//-------------------------------------
							// Check if we have reached reseed max
							currentSeed := float64(encoder.GetReseedCounter())
							if currentSeed > (float64(maxSeed) * float64(reseedPercent)) {
								//---------------------------
								// Uninstantiate the Encoder
								encoderStatus := encoder.Uninstantiate()
								if encoderStatus != mte.Status_mte_status_success {
									//--------------------------------------
									// Handle Encoder uninstantiate failure
									errorMessage := "Encoder uninstantiate error (" + mte.GetStatusName(encoderStatus) + "): " + mte.GetStatusDescription(encoderStatus) + "\n"
									fmt.Println(errorMessage)
								}

								//------------------------
								// Call Handshake Method
								// This also re-creates Encoder and Decoder
								retcode, err := PerformHandshakeWithServer(clientId)
								if err != nil {
									fmt.Println("Error: " + err.Error() + " Code: " + strconv.Itoa(retcode))
								}
							} else {
								//--------------------
								// Save state Encoder
								encoderState = encoder.SaveStateB64()
							}
						}
					}
					break
				}
				//---------------------------------------
				// If we are using MTE encrypt the chunk
				if useMte {
					if n < chunkSize {
						buf = buf[:n]
					}
					//-----------------------------------------------------------
					// Encrypt the chunk
					encoderStatus := encoder.EncryptChunk(buf)
					if encoderStatus != mte.Status_mte_status_success {
						fmt.Fprintf(os.Stderr, "Encode error (%v): %v\n",
							mte.GetStatusName(encoderStatus), mte.GetStatusDescription(encoderStatus))
						break
					}
				}
				_, _ = wr.Write(buf[:n])
			}
		}()
		//--------------------------
		// Construct request with rd
		req, _ := http.NewRequest("POST", uri, rd)
		//------------------------------------------------------
		// If we have an access token add authentication header
		if access_token != "" {
			// Create a Bearer string by appending string access token
			var bearer = "Bearer " + access_token
			// add authorization header to the req
			req.Header.Add("Authorization", bearer)
		}

		req.Header.Set(clientIdHeader, clientId)
		req.ContentLength = totalSize
		//-----------------
		// Process request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err.Error())
			return errorReadingResponse, err
		} else {
			body := &bytes.Buffer{}
			_, _ = body.ReadFrom(resp.Body)
			defer resp.Body.Close()

			//------------------------------------------
			// Marshal json response to Response object
			hrBytes, _ := ioutil.ReadAll(body)
			var serverResponse ResponseModel[string]
			json.Unmarshal(hrBytes, &serverResponse)
			if !serverResponse.Success {
				errorMessage := "Error back from server: " + serverResponse.Message + " Code: " + strconv.Itoa(errorFromServer)
				fmt.Println(errorMessage)
				return errorFromServer, errors.New(errorMessage)
			}
			//------------------
			// set access token
			access_token = serverResponse.access_token

			var decodedText []byte
			//-----------------------------------------------------
			// Decode the response message if we are using the MTE
			decoder := mte.NewMkeDecDef()
			defer decoder.Destroy()
			if useMte {
				//--------------------------------------------
				// Base64 Decode server response  to []byte
				encodedDatab64 := make([]byte, base64.StdEncoding.DecodedLen(len(serverResponse.Data)))
				n, err := base64.StdEncoding.Decode(encodedDatab64, []byte(serverResponse.Data))
				if err != nil {
					errorMessage := "Error base64 decode encoded data: " + err.Error() + " Code: " + strconv.Itoa(errorDecodingData)
					fmt.Println(errorMessage)
					return errorDecodingData, errors.New(errorMessage)
				}
				encodedData := encodedDatab64[:n]
				//----------------------------
				// Restore the Decoder state
				decoderStatus := decoder.RestoreStateB64(decoderState)
				if decoderStatus != mte.Status_mte_status_success {
					errorMessage := "Decoder restore error (" + mte.GetStatusName(decoderStatus) + "): " + mte.GetStatusDescription(decoderStatus)
					fmt.Println(errorMessage)
					return int(decoderStatus), errors.New(errorMessage)
				}

				//---------------------
				// Initialize Chunking
				decoderStatus = decoder.StartDecrypt()
				if decoderStatus != mte.Status_mte_status_success {
					errorMessage := "MTE Decoder StartDecrypt error (" + mte.GetStatusName(decoderStatus) + "): " + mte.GetStatusDescription(decoderStatus)
					fmt.Println(errorMessage)
					return int(decoderStatus), errors.New(errorMessage)
				}
				//-----------------------------------------------------------
				// The response is going to be short don't need to loop
				//-----------------------------------------------------------
				// Decrypt the chunk
				decodedData := decoder.DecryptChunk(encodedData)
				if decodedData == nil {
					errorMessage := "Decode error."
					fmt.Println(errorMessage)
					return errorDecodingData, errors.New(errorMessage)
				}
				//-----------------------
				// Finish Decode chunk
				finishDecodeChunk, decoderStatus := decoder.FinishDecrypt()
				if decoderStatus != mte.Status_mte_status_success {
					//--------------------------------------------------------
					// Decode finish decrypt unsuccessful and cannot continue
					errorMessage := "MTE Decoder FinishDecrypt error (" + mte.GetStatusName(decoderStatus) + "): " + mte.GetStatusDescription(decoderStatus)
					fmt.Println(errorMessage)
					return int(decoderStatus), errors.New(errorMessage)
				}
				//--------------------------------------------------
				// Check if there are additional bytes; if so, append
				if finishDecodeChunk != nil {
					decodedText = append(decodedData[:], finishDecodeChunk[:]...)
				} else {
					decodedText = decodedData
				}
				//-------------------------------------
				// Check if we have reached reseed max
				currentSeed := float64(decoder.GetReseedCounter())
				if currentSeed > (float64(maxSeed) * float64(reseedPercent)) {
					//---------------------------
					// Uninstantiate the Decoder
					decoderStatus := decoder.Uninstantiate()
					if decoderStatus != mte.Status_mte_status_success {
						//---------------------------------------
						// Handle Decoder uninstantiate failure
						errorMessage := "Decoder uninstantiate error (" + mte.GetStatusName(decoderStatus) + "): " + mte.GetStatusDescription(decoderStatus) + "\n"
						fmt.Println(errorMessage)
						return int(decoderStatus), errors.New(errorMessage)
					}

					//------------------------
					// Call Handshake Method
					// This also re-creates Encoder and Decoder
					retcode, err := PerformHandshakeWithServer(clientId)
					if err != nil {
						fmt.Println("Error: " + err.Error() + " Code: " + strconv.Itoa(retcode))
						return retcode, err
					}
				} else {
					//-------------------
					// Save decode state
					decoderState = decoder.SaveStateB64()
				}
			} else {
				//-------------------------------
				// Base64 Decode response string
				decodedText, err = base64.StdEncoding.DecodeString(string(serverResponse.Data))
				if err != nil {
					errorMessage := "error base64 decoding string"
					fmt.Println(errorMessage)
					return errorBase64Decoding, errors.New(errorMessage)
				}
			}
			//-------------------------------
			// Print out response from server
			fmt.Println("Response from server: " + string(decodedText))
		}
		//------------------------------------------------
		// Prompt user if they want to upload another file
		fmt.Print("\nWould you like to upload another file (y/n)?\n")
		qReader := bufio.NewReader(os.Stdin)

		uploadAgain, _ := qReader.ReadString('\n')
		//---------------------------
		// Take off carriage return
		uploadAgain = strings.Replace(uploadAgain, "\n", "", -1)
		uploadAgain = strings.Replace(uploadAgain, "\r", "", -1)

		//----------------------
		// Check user response
		if strings.ToLower(uploadAgain) == "n" {
			fmt.Println("Program stopped.")
			return endProgram, nil
		}
	}
}

/**
 * Login to API server
 * Uses default username and password
 * Uses MTE Core
 */
func LoginToServer(clientId string) (out int, err error) {
	//-----------------
	// Set login model
	// This is a demonstration, username and password should not
	// Be put in code as plain text
	login := LoginModel{
		Password: "P@ssw0rd!",
		UserName: "email@eclypses.com",
	}
	//--------------------------
	// Serialize the login model
	serializedLogin, err := json.Marshal(login)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//---------------------
	// Create the Encoder
	encoder := mte.NewEncDef()
	defer encoder.Destroy()
	//------------------------
	// Restore Encoder state
	encoderStatus := encoder.RestoreStateB64(encoderState)
	if encoderStatus != mte.Status_mte_status_success {
		errorMessage := "Encoder restore error (" + mte.GetStatusName(encoderStatus) + ", " + mte.GetStatusDescription(encoderStatus) + ")"
		fmt.Println(errorMessage)
		return int(encoderStatus), errors.New(errorMessage)
	}
	//----------------------------------
	// Encode the serialized Login Model
	encodedLogin, encoderStatus := encoder.EncodeB64(serializedLogin)
	if encoderStatus != mte.Status_mte_status_success {
		errorMessage := "Encode error " + mte.GetStatusName(encoderStatus) + " , " + mte.GetStatusDescription(encoderStatus)
		fmt.Println(errorMessage)
		return
	}
	//----------------------------
	// Save updated Encoder state
	encoderState = encoder.SaveStateB64()
	//-----------------
	// Make Http call
	loginResponse, retcode, err := MakeHttpCall(restAPIName+loginRoute, "POST", clientId, textContent, encodedLogin)
	if err != nil {
		fmt.Println(err.Error())
		return retcode, err
	}
	//-----------------------------
	// Marshal json back to class
	hrBytes := []byte(loginResponse)
	var serverResponse ResponseModel[string]
	json.Unmarshal(hrBytes, &serverResponse)
	if !serverResponse.Success {
		fmt.Println("Error back from server: " + serverResponse.Message + " Code: " + strconv.Itoa(errorFromServer))
		return errorFromServer, errors.New(serverResponse.Message)
	}
	//-----------------------------------------
	// Set access_token for next communication
	access_token = serverResponse.access_token
	//---------------------
	// Decode the response
	decoder := mte.NewDecDef()
	defer decoder.Destroy()

	//---------------------------
	// Restore the Decoder state
	decoderStatus := decoder.RestoreStateB64(decoderState)
	if mte.StatusIsError(decoderStatus) {
		errorMessage := "Decoder restore error (" + mte.GetStatusName(decoderStatus) + ", " + mte.GetStatusDescription(decoderStatus) + ")"
		fmt.Println(errorMessage)
		return int(decoderStatus), errors.New(errorMessage)
	}

	//-----------------------
	// Decode return message
	decodedMessage, decoderStatus := decoder.DecodeStrB64(serverResponse.Data)
	if mte.StatusIsError(decoderStatus) {
		errorMessage := "Decode error " + mte.GetStatusName(decoderStatus) + " , " + mte.GetStatusDescription(decoderStatus)
		fmt.Println(errorMessage)
		return int(decoderStatus), errors.New(errorMessage)
	}
	fmt.Println("Login Response: " + decodedMessage)
	decoderState = decoder.SaveStateB64()
	return 0, nil
}

/**
 * Performs Handshake with Server
 * Creates the ECDH public keys and sends them to server
 * When the client receives it back generate the shared secret
 * Then creates the Encoder and Decoder and saves the states
 *
 * clientId: clientId string
 *
 * Returns HandshakeResponse: encoderSharedSecret, decoderSharedSecret
 *
 */
func PerformHandshakeWithServer(clientId string) (out int, err error) {

	fmt.Println("Performing handshake for client: " + clientId)

	//--------------------------------------------
	// Set default return and response parameters
	var handshakeModel HandshakeModel
	handshakeModel.ConversationIdentifier = clientId

	//----------------------------------------------
	// Create Eclypses ECDH for Encoder and Decoder
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
	// If there is no license,
	// These values can be blank
	//--------------------------------
	if !mte.InitLicense(companyName, companyLicense) {
		fmt.Println("There was an error attempting to initialize the MTE License.")
		return
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

func CreateMteEncoder(timestamp string, clientId string, encoderEntropy []byte) (out int, err error) {
	encoder := mte.NewMkeEncDef()
	defer encoder.Destroy()

	//----------------------------
	// Parse nonce from timestamp
	nonce, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		panic(err)
	}

	//--------------------
	// Initialize Encoder
	//--------------------
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
	//--------------------
	// Save encoder state
	encoderState = encoder.SaveStateB64()

	return 0, nil
}

func CreateMteDecoder(timestamp string, clientId string, decoderEntropy []byte) (out int, err error) {
	decoder := mte.NewMkeEncDef()
	defer decoder.Destroy()

	//----------------------------
	// Parse nonce from timestamp
	nonce, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		panic(err)
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
	//--------------------
	// Save Decoder state
	decoderState = decoder.SaveStateB64()
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
