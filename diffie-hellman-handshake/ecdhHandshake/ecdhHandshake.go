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
	"bytes"

	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"ecdhHandshake/eclypsesEcdh"

	"github.com/google/uuid"
)

var retcode int

const (
	//--------------------
	// content type const
	jsonContent = "application/json"

	//--------------------
	// Connection url
	restAPIName    = "https://dev-echo.eclypses.com"
	handshakeRoute = "/api/handshake"

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
)

type HandshakeResponse struct {
	encoderSharedSecret string
	decoderSharedSecret string
}

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

/**
 * Main function kicks off the ECDH Handshake
 */
func main() {

	fmt.Println("Starting Go Diffie-Hellman Handshake")

	//----------------------------------------------------
	// defer the exit so all other defer calls are called
	retcode = 0
	defer func() { os.Exit(retcode) }()

	//-------------------------------
	// Initialize client parameters
	clientId := uuid.New()

	//------------------------
	// Call Handshake Method
	handshake, retcode, err := PerformHandshakeWithServer(clientId.String())
	if err != nil {
		fmt.Println("Error: " + err.Error() + " Code: " + strconv.Itoa(retcode))
		return
	}

	//-------------------------------------
	// For demonstration purposes ONLY
	// output shared secret to the screen
	fmt.Println("Completed Handshake for client: " + clientId.String())
	fmt.Println("Encoder Shared Secret: " + handshake.encoderSharedSecret)
	fmt.Println("Decoder Shared Secret: " + handshake.decoderSharedSecret)
	fmt.Println("Press enter to end program")
	fmt.Scanln()

}

/**
 * Performs Handshake with Server
 * Creates the ECDH public keys and sends them to server
 * When receives it back generates the shared secret
 *
 * clientId: clientId string
 *
 * Returns HandshakeResponse: encoderSharedSecret, decoderSharedSecret
 *
 */
func PerformHandshakeWithServer(clientId string) (out HandshakeResponse, retcode int, err error) {

	fmt.Println("Performing handshake for client: " + clientId)

	//--------------------------------------------
	// set default return and response parameters
	var handshakeResponse HandshakeResponse
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
		return handshakeResponse, errorCreatingPK, err
	}
	//----------------------------
	// Get the Decoder public key
	clientDecoderPKBytes, err := decoderEcdh.GetPublicKey()
	if err != nil {
		fmt.Println("Error creating Decoder public key: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingPK))
		return handshakeResponse, errorCreatingPK, err
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
		return handshakeResponse, errorMarshalJson, err
	}
	//----------------------------------
	// Make Http and get return string
	hsModelString, errorcode, err := MakeHttpCall(restAPIName+handshakeRoute, "POST", clientId, jsonContent, string(handshakeString))
	if err != nil {
		fmt.Println("Error making Http call: " + err.Error() + " Code: " + strconv.Itoa(errorcode))
		return handshakeResponse, errorcode, err
	}
	//-----------------------------
	// marshal json back to class
	hrBytes := []byte(hsModelString)
	var serverResponse ResponseModel[HandshakeModel]
	json.Unmarshal(hrBytes, &serverResponse)
	if !serverResponse.Success {
		fmt.Println("Error back from server: " + serverResponse.Message + " Code: " + strconv.Itoa(errorFromServer))
		return handshakeResponse, errorFromServer, errors.New(serverResponse.Message)
	}
	//--------------------------------------------
	// Base64 Decode Encoder public key to []byte
	partnerEncoderPublicKeyb64 := make([]byte, base64.StdEncoding.DecodedLen(len(serverResponse.Data.ClientEncoderPublicKey)))
	n, err := base64.StdEncoding.Decode(partnerEncoderPublicKeyb64, []byte(serverResponse.Data.ClientEncoderPublicKey))
	if err != nil {
		fmt.Println("Error base64 decode encoderPK: " + err.Error() + " Code: " + strconv.Itoa(errorDecodingPK))
		return handshakeResponse, errorDecodingPK, err
	}
	partnerEncoderPublicKeyBytes := partnerEncoderPublicKeyb64[:n]

	//--------------------------------------------
	// Base64 Decode Decoder public key to []byte
	partnerDecoderPublicKeyb64 := make([]byte, base64.StdEncoding.DecodedLen(len(serverResponse.Data.ClientDecoderPublicKey)))
	n, err = base64.StdEncoding.Decode(partnerDecoderPublicKeyb64, []byte(serverResponse.Data.ClientDecoderPublicKey))
	if err != nil {
		fmt.Println("Error base64 decode decoderPK: " + err.Error() + " Code: " + strconv.Itoa(errorDecodingPK))
		return handshakeResponse, errorDecodingPK, err
	}
	partnerDecoderPublicKeyBytes := partnerDecoderPublicKeyb64[:n]
	//-------------------------------
	// Create Encoder shared secret
	enSSBytes, err := encoderEcdh.CreateSharedSecret(partnerEncoderPublicKeyBytes, nil)
	if err != nil {
		fmt.Println("Error creating Encoder shared secret: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingSS))
		return handshakeResponse, errorCreatingSS, err
	}
	handshakeResponse.encoderSharedSecret = base64.StdEncoding.EncodeToString(enSSBytes)
	//-----------------------------
	// Create Decoder shared secret
	deSSBytes, err := decoderEcdh.CreateSharedSecret(partnerDecoderPublicKeyBytes, nil)
	if err != nil {
		fmt.Println("Error creating Decoder shared secret: " + err.Error() + " Code: " + strconv.Itoa(errorCreatingSS))
		return handshakeResponse, errorCreatingSS, err
	}
	handshakeResponse.decoderSharedSecret = base64.StdEncoding.EncodeToString(deSSBytes)
	//-------------------------
	// clear out container
	encoderEcdh.ClearContainer()
	decoderEcdh.ClearContainer()

	return handshakeResponse, 0, nil
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
	// set return string
	var returnString string
	//------------------------------------
	// If this is a POST request do this
	if connectionMethod == "POST" {
		responseBody := bytes.NewBuffer([]byte(payload))
		resp, err := http.Post(route, contentType, responseBody)
		if err != nil {
			fmt.Println("An Error Occured %v", err)
			return "", errorHttpPost, err
		}
		defer resp.Body.Close()
		//-----------------------
		//Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err.Error())
			return "", errorReadingResponse, err
		}
		//--------------------------------
		//Convert the body to type string
		returnString = string(body)
		//------------------------------------
		// If this is a GET request do this
	} else if connectionMethod == "GET" {
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
		//Convert the body to type string
		returnString = string(body)
	} else {
		fmt.Println("invalid connection request")
		return "", errorInvalidConnectionMethod, errors.New("Invalid connection request.")
	}
	return returnString, 0, nil
}
