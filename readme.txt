Usage:
compileall      - at a bash prompt

or:
gcc -o otp_enc_d otp_enc_d.c    - etc. for each of the 5 .c files

Start both daemons in the background:
  otp_enc_d [listening_port] &
  otp_dec_d [listening_port] &

Then create a key:
  keygen [keylength] > keyOutputFile
  
Encode plaintext file using created key:
  otp_enc [plaintextFile] [keyOutputFile] [encodeDaemonPort] > cipherText

To decode:
  otp_dec [cipherText] [keyOutputFile] [decodeDaemonPort] > plainText


e.g.:
$ cat plaintext1
THE RED GOOSE FLIES AT MIDNIGHT
$ otp_enc_d 57171 &
$ otp_dec_d 57172 &
$ keygen 10 > myshortkey
$ otp_enc plaintext1 myshortkey 57171 > ciphertext1
Error: key ‘myshortkey’ is too short
$ echo $?
1
$ keygen 1024 > mykey
$ otp_enc plaintext1 mykey 57171 > ciphertext1
$ cat ciphertext1
GU WIRGEWOMGRIFOENBYIWUG T WOFL
$ keygen 1024 > mykey2
$ otp_dec ciphertext1 mykey 57172 > plaintext1_a
$ otp_dec ciphertext1 mykey2 57172 > plaintext1_b
$ cat plaintext1_a
THE RED GOOSE FLIES AT MIDNIGHT
$ cat plaintext1_b
WVIOWBTUEIOBC FVTROIROUXA JBWE
$ cmp plaintext1 plaintext1_a
$ echo $?
0
$ cmp plaintext1 plaintext1_b
plaintext1 plaintext1_b differ: byte 1, line 1
$ echo $?
1
$ otp_enc plaintext5 mykey 57171
otp_enc error: input contains bad characters
$ otp_enc plaintext3 mykey 57172
Error: could not contact otp_enc_d on port 57172
$ echo $?
2
$









