package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/CPEN-431-2021/pa1-iamfauz/pb/protobuf"
	"google.golang.org/protobuf/proto"
)

// This method should return the result after connecting to the server
// The method returns two values:
// -- a bool that indicates true if the secret code was successfully obtained
//           and false otherwise, and
// -- a string that is the secret code when a code was
//             successfully obtained from the server.
//             This string is the hexadecimal representation
//             of the secret key.
func getSecretCode(serverIPaddress string,
	port int,
	studentID int) (bool, string) {

	secretKey, err := client(serverIPaddress, port, studentID)
	if err != nil {
		return false, ""
	}
	return true, secretKey
}

func main() {

	args := os.Args[1:]

	if len(args) < 3 {
		fmt.Println("Insuffient args provided. Usage: go run src/client/pa1client.go [Server IP address] [port] [Student No]")
		os.Exit(0)
	}

	serverIPAddress := args[0]

	port, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Println("Invalid port number")
		os.Exit(0)
	}
	studentID, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Println("Invalid Student ID")
		os.Exit(0)
	}

	status, key := getSecretCode(serverIPAddress, port, studentID)
	if status == true {
		fmt.Println("The secret key is", key)
	} else {
		fmt.Println("Could not obtain secret key!")
	}
}

// client wraps the whole functionality of a UDP client that sends
// a message and waits for a response coming back from the server
// that it initially targetted.
func client(serverIPaddr string, port int, studentID int) (string, error) {

	// Resolve the UDP address so that we can make use of DialUDP
	// with an actual IP and port instead of a name (in case a
	// hostname is specified).
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIPaddr, port))
	if err != nil {
		log.Fatal("Error: ", err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	// Closes the underlying file descriptor associated with the,
	// socket so that it no longer refers to any file.
	defer conn.Close()

	// Getting application level payload
	requestPayloadBytes := getApplicationRequestPayload(studentID)

	// Creating UUID hex string to be used as message ID
	uuid := uuid.NewString()
	reqMessageID := strings.ReplaceAll(uuid, "-", "")

	// Get Request/Reply Message
	requestMessage := getRequestMessage(reqMessageID, requestPayloadBytes)

	const maxRetries = 3
	const maxBufferSize = 1024
	// Note: I have set the timeout to 100 because the specifications say so and
	// the instructions are based on assumption that you are within 100ms RTT of the server.
	// Since I am in Dubai, I was only able to get the key only if I set default timeout to >= 200.
	// The average RTT for the server is 265ms when I ping from Dubai.
	timeout := 100
	numRetries := 0

	for numRetries <= maxRetries {
		// Sending Request Message to Server
		buf := []byte(requestMessage)
		_, err = conn.Write(buf)
		if err != nil {
			log.Fatal("Error: ", err)
		}

		// Setting Response timeout
		deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			log.Fatal("Marshaling error: ", err)
		}

		// Waiting for response from the server
		buf = make([]byte, maxBufferSize)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			timeout = 2 * timeout
			numRetries++
		} else {

			// Unmarshalling response to get reply message
			replyMsg := protobuf.Msg{}
			err = proto.Unmarshal(buf[0:n], &replyMsg)
			if err != nil {
				log.Fatal("Unmarshaling error: ", err)
			}
			replyMessageID := hex.EncodeToString(replyMsg.GetMessageID())
			replyChecksum := replyMsg.GetCheckSum()
			replyPayloadBytes := replyMsg.GetPayload()

			calculatedChecksum := checksum(replyMsg.GetMessageID(), replyPayloadBytes)

			// Return secretKey if valid checksum and messageID
			if calculatedChecksum == replyChecksum && reqMessageID == replyMessageID {
				secretKey := getSecretKeyFromPayload(replyPayloadBytes)
				return secretKey, nil
			}

			timeout = 2 * timeout
			numRetries++

		}

	}
	return "", errors.New("Server timed out or Response corrupted")
}

// --------Application Layer Functions ----------

// Function takes the studentID as input and returns the
// applcation-level requst payload that is to be used
// by the request-reply layer
func getApplicationRequestPayload(studentID int) []byte {
	requestPayload := protobuf.ReqPayload{
		StudentID: uint32(studentID),
	}
	requestPayloadBytes, err := proto.Marshal(&requestPayload)
	if err != nil {
		log.Fatal("Marshaling error: ", err)
	}
	return requestPayloadBytes
}

// Function extracts and returns the secret key from the
// application-level Payload
// Input:
//    - payload (bytes) - application-level payload
// Returns
//    - secretKey (string)
func getSecretKeyFromPayload(payload []byte) string {
	resPayload := protobuf.ResPayload{}
	err := proto.Unmarshal(payload, &resPayload)
	if err != nil {
		log.Fatal("Unmarshaling error: ", err)
	}
	secretKey := hex.EncodeToString(resPayload.GetSecretKey())
	return secretKey
}

// --------Request/Reply Layer Functions ----------

// Function creates the request message used in request/reply layer
// Input:
//    - messageID (string)
//    - payload (bytes)
// Returns
//    - requestMessage (bytes)
func getRequestMessage(messageID string, payload []byte) []byte {

	reqMessageIDBytes, err := hex.DecodeString(messageID)
	if err != nil {
		log.Fatal(err)
	}

	request := protobuf.Msg{
		MessageID: reqMessageIDBytes,
		Payload:   payload,
		CheckSum:  checksum(reqMessageIDBytes, payload),
	}
	requestBytes, err := proto.Marshal(&request)
	if err != nil {
		log.Fatal("Marshaling error: ", err)
	}

	return requestBytes
}

// ----------Helpers----------

// Fucntion that appends two byte arrays and
// returns its associated checksum
func checksum(val1 []byte, val2 []byte) uint64 {
	return uint64(crc32.ChecksumIEEE(append(val1[:], val2[:]...)))
}
