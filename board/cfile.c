#include <stdio.h>
#include <string.h>
#include <fcntl.h>
// #include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "../lib_rot_spirs-v4.1/RoT_SPIRS.h"


#define PORT 8080
#define HDLEN 2304
#define MLEN 2048
#define KEYLEN 256/8

int main()
{
	unsigned char pub_key[KEYLEN];
	unsigned int mask[MLEN];
	char help_data[HDLEN];
	MMIO_WINDOW ms2xl_puf_1;
    int sock = 0;
	int hd_fd;
	int mask_fd;
    struct sockaddr_in serv_addr;
	int num_read;


	system("sudo ip addr add 10.0.0.20/24 dev eth0");

	printf("1\n");

	createMMIOWindow(&ms2xl_puf_1, MS2XL_BASEADDR_PUF_1, MS2XL_LENGTH);

	printf("2\n");

	puf_as_puf(ms2xl_puf_1, 1, 256, 9, 1, pub_key);

	printf("3\n");

	for (int i = 0; i < 32; i++)
	{
		printf("%02x", pub_key[i]);
	}
	printf("\n");

	hd_fd = open("HelperData_1.bin", O_RDONLY);
    if (hd_fd < 0) {
        perror("open");
        return -1;
    }

	num_read = read(hd_fd, help_data, HDLEN);
    if (num_read < 0) {
        perror("read");
        return -1;
    }

	write(1, help_data, HDLEN);
	printf("\n");

	mask_fd = open("CHL_SM_1.bin", O_RDONLY);
    if (mask_fd < 0) {
        perror("open");
        return -1;
    }

	num_read = read(mask_fd, mask, MLEN*sizeof(int));
    if (num_read < 0) {
        perror("read");
        return -1;
    }

	write(1, mask, MLEN*sizeof(int));
	printf("\n");

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
	printf("\n");


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "10.0.0.10", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    send(sock, pub_key, KEYLEN, 0);
	send(sock, help_data, HDLEN, 0);
	send(sock, mask, MLEN*sizeof(int), 0);

    printf("Hello message sent\n");
	close(hd_fd);
	close(mask_fd);
	closeMMIOWindow(&ms2xl_puf_1);

	return 0;
}