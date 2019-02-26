/*******************************************************************************
 * otp_dec_d.c
 * Parker Howell
 * 12-1-17
 * Usage: otp_dec_d <serverport> &
 * Description - Attempts to open a server daemon on serverport. If successful
 * will listen for and accept up to 5 connectins at a time. Each connection will
 * be forked off to its own child process. Each child process will listen
 * for the client to validate itself and send the ciphertext and keytext 
 * information. Once the child process has that information, it will combine
 * the cipher and key messages to make the plain text. The plain text will be 
 * returned to the client and the connection will be closed.
 *
 * ****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>



// global array and count to track child processes
pid_t pidArray[6];  // hold unreaped child process id's
int pidCount = 0;   // track how many child PID's in pidArray



// Error function used for reporting issues
void error(const char *msg) { 
	perror(msg); 
	exit(1); 
}




/*******************************************************************************
 * decryptMsg
 * takes the message in the cipherBuff and the keyBuff and combines them to form
 * a plain text which will be located in the cipherBuff location. Overwrites
 * the old cipherBuff values.
 *
 * Note: 'A' = 65, 'Z' = 90
 *
 * ****************************************************************************/
void decryptMsg(char* cipherBuff, char* keyBuff, int size){
	int i,   // for looping
	    x,   // holds cipherbuff "chars"
	    y,   // holds keyBuff "chars"
	    z;   // holds the difference of cipher and key Buff "chars

	// decrypt each char one by one
	for (i = 0; i < size; i++){
		// convert chars to ints
		// for the cipherBuff
		// if A - Z
		if (cipherBuff[i] != ' '){
			// subtract 65 to get us to values in range 0 - 25
			x = (int)cipherBuff[i] - 65;
		}
		// else if ' ' 
		else
			x = 26;
		// for the keyBuff
		// if A - Z
		if (keyBuff[i] != ' '){
			// subtract 65 to get us to values in range 0 - 25
			y = (int)keyBuff[i] - 65;
		}
		// else if ' '
		else
			y = 26;

		// subtract the key
		z = (x - y);
		// if negative add 27 for wraparound
		if (z < 0){
			z += 27;
		}

		// convert the int value back to a capitol letter
		z += 65;

		// add it back to cipherBuff
		if (z == 91)
			cipherBuff[i] = ' ';
		else
			cipherBuff[i] = z;
	}
}




/*******************************************************************************
 * addPid
 * As background processes are created they are added to the pidArray and the
 * count is incremented.
 *
 * ****************************************************************************/
void addPid(pid_t pid){
	pidArray[pidCount] = pid;
	pidCount++;
}




/*******************************************************************************
 * removePid
 * searches for (and should find) PID of a recently finished background process.
 * When found the pid is removed from the array, the array count is decremented,
 * and the pid values after the found pid are shifted down to fill the gap.
 *
 * ****************************************************************************/
int removePid(pid_t targetPid){
	int i;
	int index = -1;

	// loop throught pidArray looking for index of out target pid
	for (i = 0; i < pidCount; i++){
		// if we find it record location and break loop
		if (pidArray[i] == targetPid){
			index = i;
			break;
		}
	}
	// if we found the index
	if (index != -1){
		// shift pids down overwriting pid we want to remove
		for (index; index < (pidCount) - 1; index++){
			pidArray[index] = pidArray[index + 1];
		}
		// decrement our count of pid's in the array
		pidCount--;
	}
}




/*******************************************************************************
 * reapChildren
 * loops through pidArray and checks if any of the processes within have 
 * finished. If so the process completin information is printed and the pid
 * is removed from the pidArray. 
 *
 * ****************************************************************************/
 void reapChildren(){
	//printf("in reapChildren\n");
	int i;          // for looping
	int ret;        // tracks if removePid succeedes or fails
	int childExit;  // stores result of how child exited
	pid_t pid;    // holds return from waitpid call
	// check each of the unreaped processes
	for (i = 0; i < pidCount; i++){
		pid = waitpid(pidArray[i], childExit, WNOHANG);
		// if we reapd a process
		if ((int)pid > 0){
			// remove the reaped child from the pidArray
			removePid(pid);
			//printf("reaped child: %d\n", (int)pid);
			i--;
			if (i < 0)
				return;
		}
	}
 }




/*******************************************************************************
 * killBG
 * on program exit, loops through the array of background processes and
 * terminates them.
 *
 * ****************************************************************************/
void killBG(){
	int i;          // for looping
	int childExit;  // stoes result of how child exited

	// for each child processes
	for (i = 0; i < pidCount; i++){
		kill(pidArray[i], SIGTERM);
	}
}




/*******************************************************************************
 * reapBG
 * should be used after killBG. Loops through array of background process ids
 * and because they should all be killed, proceedes to reap them.
 *
 * ****************************************************************************/
void reapBG(){
	int i;         // for looping
	int childExit;  // stores result of how child exited

	// for each unreaped process
	for (i = 0; i < pidCount; i++){
		waitpid(pidArray[i], childExit, 0);
	}
}




/*******************************************************************************
 * reapProc
 * called on receipt of a SIGTERM signal, kills off remaining child processes
 * and then reaaps them.
 *
 * ****************************************************************************/
void reapProc(){
	killBG();
	reapBG();
	exit(1);
}


/*******************************************************************************
 * main
 * main checks passed in arguments and then attempts to open a connection
 * on the supplied argument, serverport. If successful we wait for up to five
 * incoming connections at a time and accept them as we can. Each accepted
 * connection is forked off where in the child process the clients message will
 * be encoded to a plain text. The plain text is then sent back to the 
 * client.
 *
 * ****************************************************************************/
int main(int argc, char *argv[])
{
	int listenSocketFD, estabConnFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;
	
	char buffer[11];    // to determine the length of cipher and key msgs
	pid_t spawnPid;     // forked child process id
	char* cipherBuff;    // will hold cipher text msg from client
	char* keyBuff;      // will hold key text msg form client
	char* tempBuff;     // will hold msg segments



	// to handle killall signal from grading script
	struct sigaction SIGTERM_action = {0};

	// fill the struct
	SIGTERM_action.sa_handler = reapProc;
	sigfillset(&SIGTERM_action.sa_mask);
	SIGTERM_action.sa_flags = 0;

	// register the struct to the signal
	sigaction(SIGTERM, &SIGTERM_action, NULL);




	// Check usage & args
	if (argc < 2 || argc > 2) { 
		fprintf(stderr,"USAGE: %s port\n", argv[0]); 
		exit(1); 
	} 

	// Set up the address struct for this process (the server)
	// Clear out the address struct
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); 
	
	// Get the port number, convert to an integer from a string
	portNumber = atoi(argv[1]); 

	// validate port number
	if (portNumber < 0 || portNumber > 65535){
		fprintf(stderr, "ERROR: port number out of range\n");
		exit(1);
	}

	// Create a network-capable socket
	serverAddress.sin_family = AF_INET; 
	
	// Store the port number
	serverAddress.sin_port = htons(portNumber); 
	
	// Any address is allowed for connection to this process
	serverAddress.sin_addr.s_addr = INADDR_ANY; 

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); 
	if (listenSocketFD < 0) {
		error("ERROR opening socket");
	}

	// Enable the socket to begin listening
	// Connect socket to port
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, 
				sizeof(serverAddress)) < 0) 
		error("ERROR on binding");
	
	// Flip the socket on - it can now receive up to 5 connections
	listen(listenSocketFD, 5); 
	//printf("listening for connections\n");

	// Get the size of the address for the client that will connect
	sizeOfClientInfo = sizeof(clientAddress);
	
	// Accept a connection, blocking if one not available until one connects
	// always try to open up incoming connections
	while(1){
		// check for any finished background processes
		reapChildren();

		// Accept the connection
		estabConnFD = accept(listenSocketFD, 
				(struct sockaddr *)&clientAddress, 
				&sizeOfClientInfo); 
		if (estabConnFD < 0) {
			error("ERROR on accept");
		}
		//printf("connection accepted\n");

		// fork off a new process to handle encription
		spawnPid = fork();
		
		// check for error and handle child process
		switch(spawnPid){
			// if fork error
			case -1:
				error("ERROR forking new process\n");
				break;
			
			// handle child process
			case 0:
				//printf("in child process\n");
				// reset the buffer
				memset(buffer, '\0', sizeof(buffer));
		
				// Read the client's send flag from the socket
				charsRead = recv(estabConnFD, buffer, 1, 0);	
				if (charsRead < 0) {
					error("ERROR reading from socket");
				}
	
				//printf("SERVER: rec from the client: \"%s\"\n",
				//		buffer);
				if (strcmp(buffer, "D") != 0){
					// send err back to client
					send(estabConnFD, "error", 5, 0);
					//error("SERVER: connection not allowed");
					exit(1);
				}
	
				// Send a Success message back to the client
				charsRead = send(estabConnFD, "goods", 5, 0); 
				if (charsRead < 0) {
					error("ERROR writing to socket");
				}

				//printf("SERVER: connection good\n");

				// get the size of the messages
				charsRead = recv(estabConnFD, buffer, 10, 0);
				if (charsRead < 0) {
					error("ERROR reading msg size");
				}
				//printf("SERVER: msg size is %s\n", buffer);

				// change string val to int
				int size = atoi(buffer);
				//printf("SERVER: each msg size: ..%d..\n", size);

				
				
				// create buffers for holding cipher and key text
				cipherBuff = calloc(size + 1, sizeof(char));	
				keyBuff = calloc(size + 1, sizeof(char));
				tempBuff = calloc(size + 1, sizeof(char));
				

				// tracks if we have read the whole msg
				int readTotal = 0;
				int toRead = size;

				// get the cipher text
				while (readTotal < toRead){
					charsRead = recv(estabConnFD, 
						tempBuff, toRead, 0); 
					
					// concat the msg segment
					strcat(cipherBuff, tempBuff);
					// reset the tempBuff
					memset(tempBuff, '\0', size + 1);

					readTotal += charsRead;
					toRead -= charsRead;
				}
				//printf("SERVER: cipher is: %s\n", cipherBuff);
				//printf("SERVER: cipher is %d bytes\n", strlen(cipherBuff));

				// discard sentinel
				charsRead = recv(estabConnFD, buffer, 1, 0); 
				
				
				// reset trackers
				readTotal = 0;
				toRead = size;
				memset(tempBuff, '\0', size + 1);
				
				// get the key text
				while (readTotal < toRead){
					charsRead = recv(estabConnFD, 
						keyBuff, size, 0);
					
					// concat the msg segment
					strcat(keyBuff, tempBuff);
					// reset the tempBuff
					memset(tempBuff, '\0', size + 1);

					readTotal += charsRead;
					toRead -= charsRead;
				}	
				//printf("SERVER: key is: %s\n", keyBuff);
				//printf("SERVER: key is %d bytes\n", strlen(keyBuff));



				// decrypt the message
				decryptMsg(cipherBuff, keyBuff, size);
				//printf("SERVER: plaintext is: %s\n", cipherBuff);
				//printf("SERVER: plaintext is %d bytes\n", strlen(cipherBuff));

					
				// tracks if we sent whole msg
				int totalSent = 0;
				int toSend = size;

				// send decrypted msg back to client
				while (totalSent < size){
					charsRead = send(estabConnFD, 
						(cipherBuff + totalSent),
					       	toSend, 0);	
					if (charsRead < 0) {
						error("ERROR writing plaintextto socket");
					}
					
					totalSent += charsRead;
					toSend -= charsRead;
				}
				//printf("SERVER sent plain: %d bytes\n", charsRead);



				// wait for send buffer to clear
				int checkSend = -5;
				do{
					ioctl(estabConnFD, TIOCOUTQ, &checkSend);
				} while (checkSend > 0);

				if (checkSend < 0)
					error("ioctl error");




				// free buff memory
				if (cipherBuff){
					free(cipherBuff);
				}
				if (keyBuff){
					free(keyBuff);
				}
				if (tempBuff){
					free(tempBuff);
				}

				// Close the childs socket 	
				close(estabConnFD); 
				exit(1);
				break;

			// handle parent process
			default:
				// Close the parents socket 	
				close(estabConnFD);

				// track the spawned processes for reaping
				addPid(spawnPid);

				// parent loops back to top of while
				break;
		}
	}	

	// we should necer get here as the server should run "forever" but...
	// Close the listening socket
	close(listenSocketFD); 
	return 0; 
}









