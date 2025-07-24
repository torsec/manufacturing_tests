#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

// #include <openssl/x509.h>
// #include <openssl/x509v3.h>
// #include <openssl/evp.h>
// #include <openssl/pem.h>
// #include <openssl/err.h>

#include "ed25519.h"
#include "x509custom.h"

#define PORT 8080
#define HDLEN 2304
#define MLEN 2048
#define KEYLEN 256 / 8

#define FILE_CERT_MAN "cert_manifacturer.der"
#define FILE_PRIVKEY_MAN "priv_key_manifacturer.bin"
#define FILE_PUBKEY_MAN "pub_key_manifacturer.bin"

#define FILE_PRIVKEY_PP "priv_key_platform_provider.bin"
#define FILE_PUBKEY_PP "pub_key_platform_provider.bin"

// #define OPENSSL 1
// #define GEN_CERT_MAN 1
// #define TAKE_VALUES 1

off_t getFileSize(const char *filename) {
  struct stat st;

  if (stat(filename, &st) == 0)
    return st.st_size;

  return -1;
}

int main() {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  char helper_data[HDLEN];
  unsigned char pub_key[KEYLEN];
  int mask[MLEN];
  char *hello = "Hello from server";
  int file_fd;
  unsigned char device_root_key_priv[64];
  unsigned char device_root_key_pub[32] = {};
  int dim = 250;
  const char *fileName = "/home/lo/Documents/PhD/spirs/board/out.bin";
  char hexkey[128];
  int ret;
  unsigned char man_key_priv[64];
  unsigned char man_key_pub[32] = {};
  unsigned char pp_key_priv[64];
  unsigned char pp_key_pub[32] = {};
  unsigned int sm_size = 0x1ff000;
  unsigned char sm_signature[64];
  unsigned char kernel_signature[64];
  unsigned char *buffer;
  unsigned char sm_hash[64];

#ifdef GEN_CERT_MAN

  unsigned char man_seed[] = {0x96, 0xa3, 0x26, 0x30, 0x24, 0x30, 0x0e, 0x06,
                              0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
                              0x97, 0xf5, 0x64, 0xbc, 0x24, 0x4a, 0x7d, 0xe8,
                              0xa0, 0x15, 0xa4, 0xe8, 0xb6, 0x05, 0xf9, 0xa8};

  ed25519_create_keypair(man_key_pub, man_key_priv, man_seed);

  mbedtls_x509write_cert cert_man;
  mbedtls_x509write_crt_init(&cert_man);

  // Setting the name of the issuer of the cert

  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert_man, "CN=Manufacturer");
  if (ret != 0) {
    return 0;
  }

  // Setting the name of the subject of the cert

  ret =
      mbedtls_x509write_crt_set_subject_name_mod(&cert_man, "CN=Manufacturer");
  if (ret != 0) {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_man;
  mbedtls_pk_init(&subj_key_man);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_man;
  mbedtls_pk_init(&issu_key_man);

  // Parsing the private key of the embedded CA that will be used to sign the
  // certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key_man, man_key_pub, 64, 1);
  if (ret != 0) {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_man, man_key_priv, 32, 0);
  if (ret != 0) {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its
  // certificate
  ret = mbedtls_pk_parse_public_key(&subj_key_man, man_key_pub, 32, 0);
  if (ret != 0) {
    return 0;
  }

  // Variable  used to specify the serial of the cert
  unsigned char serial_man[] = {0xFF};

  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_man, &subj_key_man);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_man, &issu_key_man);

  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_man, serial_man, 1);

  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_man, KEYSTONE_SHA3);

  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_man, "20230101000000",
                                           "20250101000000");
  if (ret != 0) {
    return 0;
  }
  mbedtls_x509write_crt_set_basic_constraints(&cert_man, 1, 10);

  mbedtls_x509write_crt_set_key_usage(&cert_man,
                                      MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                          MBEDTLS_X509_KU_KEY_CERT_SIGN);

  unsigned char cert_der_man[1024];
  // length of the cert in der format
  int effe_len_cert_der_man;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der
  // format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_man, cert_der_man, 1024, NULL,
                                  NULL); //, test, &len);
  if (ret != 0) {
    effe_len_cert_der_man = ret;
  } else {
    return 0;
  }

  // certificate in der format
  unsigned char *cert_real_man = cert_der_man;
  // effe_len_cert_der stands for the length of the cert, placed starting from
  // the end of the buffer cert_der
  int dif_man = 1024 - effe_len_cert_der_man;
  // cert_real points to the starts of the cert in der format
  cert_real_man += dif_man;

  for (int i = 0; i < effe_len_cert_der_man; i++) {
    printf("%02x", cert_real_man[i]);
  }

  printf("\n");

  file_fd = open(FILE_PUBKEY_MAN, O_WRONLY | O_CREAT, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (write(file_fd, man_key_pub, KEYLEN) < 0) {
    perror("write");
    return -1;
  }

  close(file_fd);

  file_fd = open(FILE_PRIVKEY_MAN, O_WRONLY | O_CREAT, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (write(file_fd, man_key_priv, KEYLEN * 2) < 0) {
    perror("write");
    return -1;
  }

  close(file_fd);

  file_fd = open(FILE_CERT_MAN, O_WRONLY | O_CREAT, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (write(file_fd, cert_real_man, effe_len_cert_der_man) < 0) {
    perror("write");
    return -1;
  }

  close(file_fd);

#else // GEN_CERT_MAN
  file_fd = open(FILE_PUBKEY_PP, O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, pp_key_pub, KEYLEN * sizeof(unsigned char)) < 0) {
    perror("read");
    return -1;
  }

  file_fd = open(FILE_PRIVKEY_PP, O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, pp_key_priv, 2 * KEYLEN * sizeof(unsigned char)) < 0) {
    perror("read");
    return -1;
  }

  file_fd = open(FILE_PUBKEY_MAN, O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, man_key_pub, KEYLEN * sizeof(unsigned char)) < 0) {
    perror("read");
    return -1;
  }

  file_fd = open(FILE_PRIVKEY_MAN, O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, man_key_priv, 2 * KEYLEN * sizeof(unsigned char)) < 0) {
    perror("read");
    return -1;
  }

  for (int i = 0; i < 2 * KEYLEN; i++) {
    printf("%02x", man_key_priv[i]);
  }

  printf("\n");

  for (int i = 0; i < KEYLEN; i++) {
    printf("%02x", man_key_pub[i]);
  }

  printf("\n");

#endif // GEN_CERT_MAN

#ifndef TAKE_VALUES
  system("sudo ip addr add 10.0.0.10/24 dev eno1");
  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    return -1;
  }

  // Forcefully attaching socket to the port
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("setsockopt");
    return -1;
  }
  address.sin_family = AF_INET;
  inet_pton(AF_INET, "10.0.0.10", &(address.sin_addr));
  address.sin_port = htons(PORT);

  // Bind the socket to the network address and port
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    return -1;
  }
  if (listen(server_fd, 3) < 0) {
    perror("listen");
    return -1;
  }
  if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                           (socklen_t *)&addrlen)) < 0) {
    perror("accept");
    return -1;
  }

  read(new_socket, pub_key, KEYLEN);
  read(new_socket, helper_data, HDLEN);
  read(new_socket, mask, MLEN * sizeof(int));

  file_fd = open("pub_key.txt", O_WRONLY | O_CREAT, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (write(file_fd, pub_key, KEYLEN) < 0) {
    perror("write");
    return -1;
  }

  close(file_fd);

  file_fd = open("helper_data.bin", O_WRONLY | O_CREAT, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (write(file_fd, helper_data, HDLEN) < 0) {
    perror("write");
    return -1;
  }

  close(file_fd);

  file_fd = open("mask.bin", O_WRONLY | O_CREAT, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (write(file_fd, mask, MLEN * sizeof(int)) < 0) {
    perror("write");
    return -1;
  }

  close(file_fd);

  send(new_socket, hello, strlen(hello), 0);
  printf("Finished\n");

#else // TAKE_VALUES

  file_fd = open("mask.bin", O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, mask, MLEN * sizeof(int)) < 0) {
    perror("read");
    return -1;
  }

  close(file_fd);

  file_fd = open("pub_key.txt", O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, pub_key, KEYLEN * sizeof(unsigned char)) < 0) {
    perror("read");
    return -1;
  }

  close(file_fd);

  file_fd = open("helper_data.bin", O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, helper_data, HDLEN * sizeof(char)) < 0) {
    perror("read");
    return -1;
  }

  close(file_fd);

#endif // TAKE_VALUES

  close(file_fd);

  //  Certificate and key generation

  ed25519_create_keypair(device_root_key_pub, device_root_key_priv, pub_key);

  for (int i = 0; i < 32; i++) {
    printf("%02x", device_root_key_pub[i]);
  }

  printf("\n");

  for (int i = 0; i < 64; i++) {
    printf("%02x", device_root_key_priv[i]);
  }

  printf("\n");

  mbedtls_x509write_cert cert_root;
  mbedtls_x509write_crt_init(&cert_root);

  // Setting the name of the issuer of the cert

  ret =
      mbedtls_x509write_crt_set_issuer_name_mod(&cert_root, "CN=Manufacturer");
  if (ret != 0) {
    return 0;
  }

  // Setting the name of the subject of the cert

  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_root,
                                                   "CN=Root of Trust");
  if (ret != 0) {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_test;
  mbedtls_pk_init(&subj_key_test);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_test;
  mbedtls_pk_init(&issu_key_test);

  ret = mbedtls_pk_parse_public_key(&issu_key_test, man_key_priv, 64, 1);
  if (ret != 0) {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_test, man_key_pub, 32, 0);
  if (ret != 0) {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&subj_key_test, device_root_key_pub, 32, 0);
  if (ret != 0) {
    return 0;
  }

  // Variable  used to specify the serial of the cert
  unsigned char serial_root[] = {0x0A};

  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_root, &subj_key_test);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_root, &issu_key_test);

  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_root, serial_root, 1);

  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_root, KEYSTONE_SHA3);

  mbedtls_x509write_crt_set_key_usage(&cert_root,
                                      MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                          MBEDTLS_X509_KU_KEY_CERT_SIGN);

  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20240101000000",
                                           "20250101000000");
  if (ret != 0) {
    return 0;
  }
  mbedtls_x509write_crt_set_basic_constraints(&cert_root, 1, 10);

  unsigned char cert_der_root[1024];
  int effe_len_cert_der_root;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der
  // format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_root, cert_der_root, 1024, NULL,
                                  NULL); //, test, &len);
  if (ret != 0) {
    effe_len_cert_der_root = ret;
  } else {
    return 0;
  }

  unsigned char *cert_real_root = cert_der_root;
  // effe_len_cert_der stands for the length of the cert, placed starting from
  // the end of the buffer cert_der
  int dif_root = 1024 - effe_len_cert_der_root;
  // cert_real points to the starts of the cert in der format
  cert_real_root += dif_root;

  printf("certificate length: %d\n", effe_len_cert_der_root);
  printf("cerificate device root key\n");
  for (int i = 0; i < effe_len_cert_der_root; i++)
    printf("%02x", cert_real_root[i]);
  printf("\n-------------------------------------------------------\n");

  int payload_size = (int)getFileSize("fw_payload.bin");
  if (payload_size >= 0) {
    printf("Size: %d bytes\n", payload_size);
  }

  buffer = (unsigned char *)malloc(payload_size * sizeof(unsigned char));

  file_fd = open("fw_payload.bin", O_RDONLY, 0644);
  if (file_fd < 0) {
    perror("open");
    return -1;
  }

  if (read(file_fd, buffer, payload_size * sizeof(unsigned char)) < 0) {
    perror("read");
    return -1;
  }

  close(file_fd);

  // sha3(buffer, sm_size, sm_hash, 512);

  // for (int i = 0; i < 64; i++)
  // 	printf("%02x", sm_hash[i]);

  // printf("\n");

  ed25519_sign(sm_signature, buffer, sm_size, pp_key_pub, pp_key_priv);
  ed25519_sign(kernel_signature, buffer + sm_size, payload_size - sm_size,
               pp_key_pub, pp_key_priv);
  int res = ed25519_verify(kernel_signature, buffer + sm_size,
                           payload_size - sm_size, pp_key_pub);

  for (int i = 0; i < 64; i++)
    printf("%02x", sm_signature[i]);

  printf("\n");

  printf("\n%d\n", res);

#ifdef OPENSSL
  EVP_PKEY *pkey, *ca_pkey;
  X509 *x509 = X509_new();
  const unsigned char *p = device_root_key_priv;

  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                      device_root_key_priv, 32);
  if (!pkey) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  printf("reading the CA key\n");

  FILE *fp = fopen("private_key.pem", "r");
  if (!fp) {
    perror("fopen");
    return -1;
  }
  ca_pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  if (!ca_pkey) {
    fprintf(stderr, "Failed to read private key CA\n");
    return -1;
  }

  fclose(fp);

  X509_NAME *name;
  name = X509_get_subject_name(x509);
  if (!name) {
    fprintf(stderr, "Failed to get subject name\n");
    return -1;
  }

  if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US",
                                 -1, -1, 0) != 1 ||
      X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                 (unsigned char *)"My Company", -1, -1,
                                 0) != 1 ||
      X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 (unsigned char *)"localhost", -1, -1,
                                 0) != 1) {
    fprintf(stderr, "Failed to add entry to subject name\n");
    return -1;
  }
  printf("Creating certificate\n");

  EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                 device_root_key_pub, 32);
  if (!pubkey) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  if (X509_set_pubkey(x509, pubkey) != 1) {
    fprintf(stderr, "Failed to set public key\n");
    return -1;
  }

  int result = X509_sign(x509, ca_pkey, EVP_sha256());
  if (result == 0) {
    fprintf(stderr, "Failed to sign the certificate\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  printf("Writing certificate\n");
  fp = fopen("drk.der", "wb");
  if (!fp) {
    perror("Unable to open file");
    return -1;
  }

  if (i2d_X509_fp(fp, x509) <= 0) {
    fprintf(stderr, "Failed to write certificate\n");
    return -1;
  }

  PEM_write_X509(stdout, x509);

  unsigned char *der = NULL;
  int len = i2d_X509(x509, &der);

  for (int i = 0; i < len; i++) {
    printf("%02X", der[i]);
  }

  printf("\n");

  fclose(fp);

  // Clean up
  X509_free(x509);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(pubkey);
  EVP_PKEY_free(ca_pkey);
  OPENSSL_free(der);

#endif // OPENSSL

  // write in the file

  dim = effe_len_cert_der_root;

  int file = open(fileName, O_WRONLY | O_CREAT, 0644);
  if (file != -1) {
    write(file, mask, sizeof(mask));
    write(file, &dim, sizeof(dim));
    write(file, cert_real_root, effe_len_cert_der_root);
    write(file, helper_data, sizeof(helper_data));
    write(file, &payload_size, sizeof(payload_size));
    write(file, sm_signature, sizeof(sm_signature));
    write(file, kernel_signature, sizeof(kernel_signature));
    close(file);

    printf("Creation of the file completed\n");
  } else {
    fprintf(stderr, "Can't open the file %s\n", fileName);
  }

  free(buffer);

  return 0;
}
