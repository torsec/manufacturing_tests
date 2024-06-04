# Repsitory for manifacturing the SPIRS board



folder "board" contains the application that must be cross compiled and runned on the board
- lib folder has all the dependencies
- cfile.c is the application, it obtain the values from the puf, configure the network connection and connect to the socket created by the server and passes the files on the socket. to compile use`` ${COMPILER} cfile.c -L./lib -lrotspirs -lm -o ${EXE} --static `` and then move the executable on keystone.

folder "bootrom" contains the modification necessary to the bootrom. 
- "main.c" needs to be inserted in the bootrom project instead on the old "main.c"

folder "server" contains the data necessary to run the server on the pc
- all required certificates and keys
- the dependency archive "liball.c"
- the file "server.c" requires to be compiled with the library "liball.c" and is in charge of communicating with the board: configure the network, opens the socket, wait for the board data, creates certificate and additional data (sm and kernel signatures). requires to have the rootfs and fw_payload in the same folder. compiled with `` gcc -o server server.c -L. -lall ``. it creates the additional data that are required to flash in the SD.
- the script "flash.sh" flashes the values in the SD, creates the partitions and copies the rootfs, fwpayload and the additional data in the SD. requires to have them in the same folder.
