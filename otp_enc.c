/*******************************************************************************
 * otp_enc.c
 * Parker Howell
 * 12-1-17
 * Usage - "opt_enc <plaintext> <keytext> <serverport>"
 * Description - checks that the keytext is of valid length (at least as long
 * as the plaintext) that both plain and key texts do not contain invalid 
 * characters, and then connects to the otp_enc_d server specified at 
 * serverport. Once connected this program sends the information to the server
 * so it can be encoded. It then waits for the server to return the encoded
 * message and once recieved, prints the encoded message to stdout.
 *
 * ****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/ioctl.h>


// Error function used for reporting issues
void error(const char *msg) {
       perror(msg); exit(1);
} 


/*******************************************************************************
 * getSizeOf
 * takes a file name as an argument and tries to open that file. If it can it
 * will determine and return the size of that file.
 *
 * ****************************************************************************/
int getSizeOf(char* theFile){
	FILE* fp;         // file pointer
	int fileLength;   // stores size of file
	
	// open file for reading
	fp = fopen(theFile, "r");
	if (fp == NULL){
		fprintf(stderr, "Error opening file: %s\n", theFile);
		exit(1);
	}
	
	// move to end of file
	fseek(fp, 0, SEEK_END);
	//get the size
	fileLength = ftell(fp);
	// close the file
	fclose(fp);

	// return the size of the file
	return(fileLength);
}




/*******************************************************************************
 * fillBuff
 * opens theFile and reads the contents into buffer. closes the file when done.
 *
 * ****************************************************************************/
void fillBuff(char* theFile, int fileLength, char* buffer){
	FILE* fp;       // file pointer to opened file
	int readSize;   // stores number of bytes read 
	
	// open the file for reading
	fp = fopen(theFile, "r");
	if (fp == NULL){	
		fprintf(stderr, "Error (fillbuff) opening file: %s\n", theFile);
		exit(1);
	}

	// read the file into the buffer
	readSize = fread(buffer, fileLength, 1, fp);
	//printf("fileLength is %d\n", fileLength);
	//printf("readSize is %d\n", readSize);
	
	// close the file
	fclose(fp);
}




/*******************************************************************************
 * checkBuff
 * checks theBuff buffer for any characters that aren't either "A - Z" or the
 * space " " character. If found an error message is printed to stderr and the
 * program exits. If no errors are found the function simply returns.
 * 
 * ****************************************************************************/
void checkBuff(char* theBuff, int buffSize){
	int i;    // for looping

	// check every char in the buffer
	for (i = 0; i < buffSize - 1; i++){
		// if the char isnt "A - Z" or " "
		if (((theBuff[i] < 65) && (theBuff[i] != 32)) 
				|| (theBuff[i] > 90)){
			//printf("bad char %c at buffer index %d\n", 
			//		theBuff[i], i);
			fprintf(stderr, 
			"otp_enc error: input contains bad characters\n");
			exit(1);
		}
	}
}




/*******************************************************************************
 * main
 * performs argument validation and checks the input files. Then proceeds to
 * assemble the message to be sent for encryption. Once the message is ready
 * main opens up a network connection to the server and sends the message to
 * it. It then waits for the return encrypted message and once recieved, prints
 * that encrypted message to stdout.
 *
 * ****************************************************************************/
int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	int plainLength;          // size of the plainText message
	int keyLength;            // size of the enc/dec key
	int msgSize;              // size of msg to send to server
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
    
	// Check usage & args
	if (argc < 4 || argc > 4) { 
		fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
		exit(1); 
	} 
	
	// Get and validate the port number
	// convert to an integer from a string
	portNumber = atoi(argv[3]); 
	if (portNumber < 0 || portNumber > 65535){
		fprintf(stderr, "Invalid port number\n");
		exit(1);
	}

	// get the size of the plain text and key text files.
	plainLength = getSizeOf(argv[1]);
	keyLength = getSizeOf(argv[2]);
	//printf("plainText is %d bytes long\n", plainLength);
	//printf("keyText is %d bytes long\n", keyLength);

	// check if key text is at least as long as the plain text
	if (keyLength < plainLength){
		fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
		exit(1);
	}

	// meke buffers so we can read plainText and keyText into them
	char* plainBuff = calloc(plainLength, sizeof(char)); 
	char* keyBuff = calloc(keyLength, sizeof(char));

	// fill those buffers with the plaintext and keytext file contents
	fillBuff(argv[1], plainLength, plainBuff);
	//printf("plainBuff: ..%s..\n", plainBuff);
	fillBuff(argv[2], keyLength, keyBuff);
	//printf("keyBuff: ..%s..\n", keyBuff);
	
	// remove trailing newlines from buffers
	plainBuff[plainLength - 1] = '\0';
	keyBuff[keyLength - 1] = '\0';
	
	// check that the buffers contain valid characters " " or "A - Z"
	checkBuff(plainBuff, plainLength);
	checkBuff(keyBuff, keyLength);


	// create the Msg we will send to the server
	// get the size we will need for Msg buffer
	// (+ 13) -  for the msg designator E, the 10 byte msg length count,
	// the sentinel @, and terminator '\0'.
	msgSize = (strlen(plainBuff) * 2) + 13;
	//printf("msgSize is: %d\n", msgSize);

	// create the Msg buffer
	char* msgBuff = calloc(msgSize, sizeof(char));
	
	// designate that msg is from opt_Enc
	strcat(msgBuff, "E");



	// make a string out of the length of plain text file
	// the string will always be 10 bytes long with leading zeros padding
	// any unused bytes.  ex:  0000001351  for a file 1351 bytes in size.
	int i;
	int plainSize;
	char* tempBuff = calloc(11, sizeof(char));
	
	// convert the int size of plaintext msg, to a string in tempBuff
	sprintf(tempBuff, "%d", plainLength - 1);
	// get how many bytes long that string is
	plainSize = strlen(tempBuff);
	// find out how many leading zeros we need to ensure standardized
	// 10 byte length.
	plainSize = 10 - plainSize;
	// concatenate the leading zeros
	for (i = 0; i < plainSize; i++){
		strcat(msgBuff, "0");
	}
	//printf("size of msg in bytes: %s\n", tempBuff);

	// add the actual size string to the zeros
	strcat(msgBuff, tempBuff);



	// concatenate the plaintext msg
	strcat(msgBuff, plainBuff);

	// add a sentinel mostly for visual confirmation of split btwn msgs
	strcat(msgBuff, "@");

	// concatenate the key msg in equal length of the plain text msg
	strncat(msgBuff, keyBuff, strlen(plainBuff));
	// msgBuff should be null terminated
	//printf("msgBuff is: ..%s..\n", msgBuff);




 
	// now to send the msg
	// Set up the server address struct
	
	// Clear out the address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); 
	
	// Create a network-capable socket
	serverAddress.sin_family = AF_INET; 
	
	// Store the port number - host to network short format
	serverAddress.sin_port = htons(portNumber); 
	
	// Convert the machine name into a special form of address
	serverHostInfo = gethostbyname("localhost"); 
	
	if (serverHostInfo == NULL) { 
		fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
		exit(0); 
	}
	
	// Copy in the address
	memcpy((char*)&serverAddress.sin_addr.s_addr, 
			(char*)serverHostInfo->h_addr, 
			serverHostInfo->h_length);

	// Create the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); 
	if (socketFD < 0) {
		error("CLIENT: ERROR opening socket");
	}

	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, 
				sizeof(serverAddress)) < 0) 
		error("CLIENT: ERROR connecting");
	//printf("CLIENT: connected to server\n");

	
	//printf("CLIENT: atempting to send %d bytes\n", strlen(msgBuff));


	// Send message to server, loop until all data sent
	int totalSent = 0;        // amount of bytes sent so far
	int toSend = msgSize;     // bytes left to send
	while (totalSent < msgSize){
		charsWritten = send(socketFD, (msgBuff + totalSent), toSend, 0); 
		if (charsWritten < 0){
		       	error("CLIENT: ERROR writing to socket");
		}

                totalSent += charsWritten;
		toSend -= charsWritten;
	}
	//printf("CLIENT: sent %d bytes to server\n", totalSent);

	// wait for send buffer to clear
	int checkSend = -5;
	do{
		ioctl(socketFD, TIOCOUTQ, &checkSend);
	} while (checkSend > 0);

	if (checkSend < 0)
		error("ioctl error");

	//printf("total sent was %d\n", totalSent);


	// Get return message from server
	// Clear out the buffer again for reuse
	memset(plainBuff, '\0', plainLength); 
	
	int readTotal = 0;
	int toRead = 5;
	while (readTotal < 5){
		// Read response for designator check - "E"
		charsRead = recv(socketFD, plainBuff, toRead, 0); 
	
		if (charsRead < 0) {
			error("CLIENT: ERROR reading from socket");
		}

		readTotal += charsRead;
		toRead -= charsRead;
	}
	//printf("CLIENT: I received this from the server: \"%s\"\n", plainBuff);
	
	// check for unallowed connection error
	if (strcmp(plainBuff, "error") == 0){
		fprintf(stderr, 
		"Error: could not contact otp_enc_d on port %d\n", portNumber);
		exit(2);
	}	
	
	// check if designator check was successful
	if (strcmp(plainBuff, "goods") == 0){
		//printf("CLIENT: good connecton ack'd\n");
	}



	// with connection verified, wait for returned cipherText
	// reuse buffs again
	memset(plainBuff, '\0', plainLength);
	memset(keyBuff, '\0', keyLength);
	//printf("CLIENT: plainBuff before cipher recv: %s\n", plainBuff);

	// get the cipher text
	readTotal = 0;              // bytes we have read so far
	toRead = plainLength - 1;   // amount of bytes we need to read
	

	//printf("CLIENT: attempting to read %d byte cipher\n", plainLength - 1);
	//printf("keyBuff can hold %d bytes\n", keyLength);
	//printf("plainBuff can hold %d bytes\n", plainLength);
	//printf("plainBuff should be empty: %d\n", strlen(plainBuff));

	// loop until we have the whole message
	while (readTotal < plainLength - 1){
		//printf("CLIENT: recv loop\n");
		//each while loop stores what it can in keyBuff
		charsRead = recv(socketFD, keyBuff, toRead, 0);
	
		if (charsRead < 0) {	
			error("CLIENT: Error reading cipher from socket");
		}
		
		// the msg segment in keyBuff is concatenated to plainBuff
		strcat(plainBuff, keyBuff);
		// reset keyBuff again
		memset(keyBuff, '\0', keyLength);

		readTotal += charsRead;
		toRead -= charsRead;
		//printf("charsRead: %d\n", charsRead);
		//printf("readTotal: %d\n", readTotal);
		//printf("toRead: %d\n", toRead);
	}

	//printf("CLIENT: cipher in plainBuff is %d bytes\n", strlen(plainBuff));

	// print the cipher to stdout
	printf("%s\n", plainBuff);

	// Close the socket
	close(socketFD); 



	// cleanup
	if (plainBuff){
		free(plainBuff);
	}
	if (keyBuff){
		free(keyBuff);
	}
	if (msgBuff){
		free(msgBuff);
	}
	if (tempBuff){
		free(tempBuff);
	}


	return(0);
}







