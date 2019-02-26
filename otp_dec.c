/*******************************************************************************
 * otp_dec.c
 * Parker Howell
 * 12-1-17
 * Usage - "opt_dec <ciphertext> <keytext> <serverport>"
 * Description - checks that the keytext is of valid length (at least as long
 * as the ciphertext) that both cipher and key texts do not contain invalid 
 * characters, and then connects to the otp_dec_d server specified at 
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
	int cipherLength;          // size of the cipherText message
	int keyLength;            // size of the enc/dec key
	int msgSize;              // size of msg to send to server
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
    
	// Check usage & args
	if (argc < 4 || argc > 4) { 
		fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]); 
		exit(1); 
	} 
	
	// Get and validate the port number
	// convert to an integer from a string
	portNumber = atoi(argv[3]); 
	if (portNumber < 0 || portNumber > 65535){
		fprintf(stderr, "Invalid port number\n");
		exit(1);
	}

	// get the size of the cipher text and key text files.
	cipherLength = getSizeOf(argv[1]);
	keyLength = getSizeOf(argv[2]);
	//printf("cipherText is %d bytes long\n", cipherLength);
	//printf("keyText is %d bytes long\n", keyLength);

	// check if key text is at least as long as the ciphertext
	if (keyLength < cipherLength){
		fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
		exit(1);
	}

	// meke buffers so we can read cipherText and keyText into them
	char* cipherBuff = calloc(cipherLength, sizeof(char)); 
	char* keyBuff = calloc(keyLength, sizeof(char));

	//printf("CLIENT: cipherBuff is %d bytes large\n", cipherLength);
	//printf("CLIENT: keyBuff is %d bytes large\n", keyLength);
	
	
	// fill those buffers with the ciphertext and keytext file contents
	fillBuff(argv[1], cipherLength, cipherBuff);
	//printf("cipherBuff: ..%s..\n", cipherBuff);
	fillBuff(argv[2], keyLength, keyBuff);
	//printf("keyBuff: ..%s..\n", keyBuff);
	
	// remove trailing newlines from buffers
	cipherBuff[cipherLength - 1] = '\0';
	keyBuff[keyLength - 1] = '\0';
	
	// check that the buffers contain valid characters " " or "A - Z"
	checkBuff(cipherBuff, cipherLength);
	checkBuff(keyBuff, keyLength);

	//printf("CLIENT: cipherBuff has %d bytes in it\n", strlen(cipherBuff));
	//printf("CLIENT: keyBuff has %d bytes in it\n", strlen(keyBuff));


	// create the Msg we will send to the server
	// get the size we will need for Msg buffer
	// (+ 13) -  for the msg designator D, the 10 byte msg length count,
	// the sentinel @, and terminator '\0'.
	msgSize = (strlen(cipherBuff) * 2) + 13;
	//printf("msgSize is: %d\n", msgSize);

	// create the Msg buffer
	char* msgBuff = calloc(msgSize, sizeof(char));
	
	// designate that msg is from opt_Dec
	strcat(msgBuff, "D");



	// make a string out of the length of cipher text file
	// the string will always be 10 bytes long with leading zeros padding
	// any unused bytes.  ex:  0000001351  for a file 1351 bytes in size.
	int i;
	int cipherSize;
	char* tempBuff = calloc(11, sizeof(char));
	
	// convert the int size of ciphertext msg, to a string in tempBuff
	sprintf(tempBuff, "%d", cipherLength - 1);
	// get how many bytes long that string is
	cipherSize = strlen(tempBuff);
	// find out how many leading zeros we need to ensure standardized
	// 10 byte length.
	cipherSize = 10 - cipherSize;
	// concatenate the leading zeros
	for (i = 0; i < cipherSize; i++){
		strcat(msgBuff, "0");
	}
	// add the actual size string to the zeros
	strcat(msgBuff, tempBuff);



	// concatenate the ciphertext msg
	strcat(msgBuff, cipherBuff);

	// add a sentinel mostly for visual confirmation of split btwn msgs
	strcat(msgBuff, "@");

	// concatenate the key msg in equal length of the ciphertext msg
	strncat(msgBuff, keyBuff, strlen(cipherBuff));
	// msgBuff should be null terminated
	//printf("msgBuff is: ..%s..\n", msgBuff);
	//printf("CLIENT: msgBuff id %d bytes long\n", strlen(msgBuff));



 
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

	//printf("CLIENT: sent %d bytes for msg\n", totalSent);


	// wait for send buffer to clear
	int checkSend = -5;
	do{
		ioctl(socketFD, TIOCOUTQ, &checkSend);
	} while (checkSend > 0);

	if (checkSend < 0)
		error("ioctl error");



	// Get return message from server
	// Clear out the buffer again for reuse
	memset(cipherBuff, '\0', cipherLength); 

	int readTotal = 0;
	int toRead = 5;
	while (readTotal < 5){	
		// Read response for designator check - "D"
		charsRead = recv(socketFD, cipherBuff, toRead, 0); 
		
		if (charsRead < 0) {
			error("CLIENT: ERROR reading from socket");
		}
	
		readTotal += charsRead;
		toRead -= charsRead;
	}
	//printf("CLIENT: I received this from the server: \"%s\"\n", cipherBuff);
	
	// check for unallowed connection error
	if (strcmp(cipherBuff, "error") == 0){
		fprintf(stderr, 
		"Error: could not contact otp_enc_d on port %d\n", portNumber);
		exit(2);
	}	
	// check if designator check was successful
	if (strcmp(cipherBuff, "goods") == 0){
		//printf("CLIENT: good connecton ack'd\n");
	}



	// with connection verified, wait for returned cipherText
	// reuse buffs again
	memset(cipherBuff, '\0', cipherLength);
	memset(keyBuff, '\0', keyLength);
	//printf("CLIENT: cipherBuff before cipher recv: %s\n", cipherBuff);

	// get the cipher text
	readTotal = 0;              // bytes we have read so far
	toRead = cipherLength - 1;   // amount of bytes we need to read
	//printf("CLIENT: toRead starts at: %d\n", toRead);
	
	// loop until we have the whole plaintext message
	while (readTotal < cipherLength - 1){
		//printf("CLIENT: recv loop\n");
		//each while loop stores what it can in keyBuff
		charsRead = recv(socketFD, keyBuff, toRead, 0);
	
		if (charsRead < 0) {	
			error("CLIENT: Error reading cipher from socket");
		}
		
		// the msg segment in keyBuff is concatenated to cipherBuff
		strcat(cipherBuff, keyBuff);
		// reset keyBuff again
		memset(keyBuff, '\0', keyLength);

		readTotal += charsRead;
		toRead -= charsRead;
		//printf("charsRead: %d\n", charsRead);
		//printf("readTotal: %d\n",readTotal );
		//printf("toRead: %d\n", toRead);
	}

	//printf("CLIENT: plain text is %d bytes\n", strlen(cipherBuff));
	// print the plain text to stdout
	printf("%s\n", cipherBuff);

	// Close the socket
	close(socketFD); 



	// cleanup
	if (cipherBuff){
		free(cipherBuff);
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







