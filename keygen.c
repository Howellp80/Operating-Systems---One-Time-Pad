/*******************************************************************************
 * keygen.c
 * Parker Howell
 * 12-1-17
 * Description - Recieves an integer value, keylength, as input and creates
 * a key of said length with a newline character appended to it. The key will 
 * consist of pseudo-random upper case alpabet chars and the "space" char. 
 * So: "A - Z" and " ".  After generating the key, it is output to standard out.
 * 
 * ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>










/*******************************************************************************
 * createKey
 * 
 *
 * ****************************************************************************/
void createKey(int keyLength){
	int i;           // for looping
	int randVal;   // holds randomly generated value
		
	// check keyLength was bigger than 0 or that atoi conv worked
	if (keyLength == 0){
		fprintf(stderr, "%s\n", "Useage2: keygen <int lengthOfKey>");
		exit(1);
	}

	// create array to hold the key
	char* theKey = calloc(keyLength + 1, sizeof(char));
	
	// fill the key with spaces and random capital letters
	for (i = 0; i < keyLength; i++){
		// get a random number between 0 - 26
		randVal = rand() % 27;
		// adjust it so it coorelates to ascii capital letters
		randVal += 65;

		// convert the random number to " " or "A - Z"
		if (randVal == 91){
			theKey[i] = ' ';
		}
		else {
			theKey[i] = (char)randVal;
		}
	}

	// add the trailing newline
	theKey[keyLength] = '\n';
	
	// print the key to stdout
	printf("%s", theKey);
}







/*******************************************************************************
 * main
 * 
 *
 * ****************************************************************************/
int main(int argc, char* argv[]){	
	// check for proper argc amount
	if (argc < 2 || argc > 2){
		fprintf(stderr, "%s\n", "Useage1: keygen <int lengthOfKey>");
	}
	
	// seed a pseudo random num generator
	srand(time(NULL));

	// create the key
	createKey(atoi(argv[1]));

	return(0);
}












