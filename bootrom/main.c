#include "uart.h"
#include "spi.h"
#include "sd.h"
#include "gpt.h"
#include <stddef.h>

#define ED25519_NO_SEED 1
#include "sha3/sha3.h"
#include "ed25519/ed25519.h"
#include "string.h"
#include "eddsa/ECC_func.h"

#include "x509custom/x509custom.h"
#include "sha3_hw/sha3_hw.h"
#include "ROT_custom.h"

typedef unsigned char byte;

extern byte sanctum_dev_public_key[32];
extern byte sanctum_dev_secret_key[64];
extern byte sanctum_sm_hash[64];
extern byte sanctum_sm_public_key[32];
extern byte sanctum_sm_secret_key[64];
extern byte sanctum_sm_signature[64];

extern byte sanctum_CDI[64];
extern byte sanctum_ECASM_pk[64];
extern byte sanctum_device_root_key_pub[64];
extern byte sanctum_cert_sm[512];
extern byte sanctum_cert_root[512];
extern byte sanctum_cert_man[512];
extern int sanctum_length_cert;
extern int sanctum_length_cert_root;
extern int sanctum_length_cert_man;
extern byte test[64];

unsigned int sanctum_sm_size = 0x1ff000;
#define DRAM_BASE 0x80000000

static const unsigned char sanctum_uds[] = {
	0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
	0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
	0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73};

static const unsigned char pub_key_manifacturer[] = {
	0x7f, 0x70, 0xec, 0x0c, 0x2a, 0x76, 0x07, 0xd3, 0x1a, 0x0b, 0x89, 0xd6,
	0x4e, 0x0f, 0x51, 0x4e, 0xf7, 0x88, 0x7d, 0x45, 0xb3, 0x2b, 0x14, 0x8b,
	0x82, 0x25, 0xd0, 0x72, 0xba, 0xf0, 0x62, 0x08};

static const unsigned char pub_key_platform_provider[] = {
	0xac, 0x56, 0x13, 0x53, 0x5c, 0x0e, 0x67, 0xf3, 0x5f, 0xb9, 0x61, 0xf2,
	0x4c, 0xc6, 0xb2, 0x81, 0x92, 0x5c, 0xf0, 0xf0, 0xc8, 0x1c, 0x69, 0x73,
	0x95, 0xd2, 0xc0, 0xcb, 0xcf, 0x94, 0x7d, 0xfe};

int main()
{
	init_uart(50000000, 115200);

	int res = gpt_find_boot_partition((uint8_t *)0x80000000UL, 2 * 16384);

	int challenge_mask_from_SD[2048];
	char help_data_from_SD[2304];
	unsigned char sd_sm_signature[64];
	unsigned char sd_kernel_signature[64];
	int sd_payload_size;

	int challenge_mask_to_print[8];
	char help_data_to_print[8];

	void *mem_addr = (void *)0xA0000000UL;
	void *mem_addr_drk;
	void *mem_addr_drk_len;
	int dim_cert;

	print_uart("Copying puf_selm_value...\r\n");
	memcpy(challenge_mask_from_SD, mem_addr, 8192);
	mem_addr += 8192;
	print_uart("Copying the dimension of the certificate...\r\n");
	memcpy(&dim_cert, mem_addr, 4);
	unsigned char certDRK[dim_cert];
	mem_addr_drk_len = mem_addr;
	mem_addr += 4;

	print_uart("Copying the certificate...\r\n");
	memcpy(certDRK, mem_addr, dim_cert);
	mem_addr_drk = mem_addr;
	mem_addr += dim_cert;
	print_uart("Copying help_data value...\r\n");
	memcpy(help_data_from_SD, mem_addr, 2304);
	mem_addr += 2304;
	memcpy(&sd_payload_size, mem_addr, 4);
	mem_addr += 4;
	memcpy(sd_sm_signature, mem_addr, 64);
	mem_addr += 64;
	memcpy(sd_kernel_signature, mem_addr, 64);

	print_uart("puf_selm value of the platform:\r\n");
	for (int i = 0; i < 2048; i++)
		print_uart_int(challenge_mask_from_SD[i]);
	print_uart("\r\n-----------------------------------------------------------\r\n");

	print_uart("help_data value of the platform:\r\n");
	for (int i = 0; i < 2304; i++)
		print_uart_byte(help_data_from_SD[i]);
	print_uart("\r\n-----------------------------------------------------------\r\n");

	print_uart("DRK certificate length:\r\n");
	print_uart_int(dim_cert);

	print_uart("\r\nDRK certificate:\r\n");
	for (int i = 0; i < dim_cert; i++)
		print_uart_byte(certDRK[i]);
	print_uart("\r\n-----------------------------------------------------------\r\n");

	print_uart("\r\nKernel Signature:\r\n");
	for (int i = 0; i < 64; i++)
		print_uart_byte(sd_kernel_signature[i]);
	print_uart("\r\n-----------------------------------------------------------\r\n");

	print_uart("\r\nSM Signature:\r\n");
	for (int i = 0; i < 64; i++)
		print_uart_byte(sd_sm_signature[i]);
	print_uart("\r\n-----------------------------------------------------------\r\n");

	print_uart("Payload size:\r\n");
	print_uart_int(sd_payload_size);

	sanctum_length_cert_root = dim_cert;

	MMIO_WINDOW ms2xl_puf_1;
	MMIO_WINDOW ms2xl_sha3_512;
	MMIO_WINDOW ms2xl_eddsa;

	createMMIOWindow(&ms2xl_puf_1, MS2XL_BASEADDR_PUF_1, MS2XL_LENGTH);
	createMMIOWindow(&ms2xl_sha3_512, MS2XL_BASEADDR_SHA3_512, MS2XL_LENGTH);
	createMMIOWindow(&ms2xl_eddsa, MS2XL_BASEADDR_EDDSA, MS2XL_LENGTH);
	unsigned char out_puf_1[256 / 8];

	puf_as_puf(ms2xl_puf_1, 1, 256, 9, out_puf_1, challenge_mask_to_print, challenge_mask_from_SD, help_data_to_print, help_data_from_SD);

	sha3_ctx_t hash_ctx;
	byte sanctum_device_root_key_priv[64];
	byte sanctum_ECASM_priv[64];

	dice_tcbInfo tcbInfo;
	init_dice_tcbInfo(&tcbInfo);
	measure m;

	unsigned char sm_data_to_hash[sanctum_sm_size];

	memcpy(sm_data_to_hash, (void *)DRAM_BASE, sanctum_sm_size);

	unsigned long long int len_to_pass = sanctum_sm_size * 8;
	sha3_hw_512(sm_data_to_hash, sanctum_sm_hash, len_to_pass, ms2xl_sha3_512, 0);

	for (int i = 0; i < 64; i++)
		print_uart_byte(sanctum_sm_hash[i]);
	print_uart("\r\n-----------------------------------------------------------\r\n");

	const unsigned char OID_algo[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A};
	memcpy(m.digest, sanctum_sm_hash, 64);
	memcpy(m.OID_algho, OID_algo, 9);
	m.oid_len = 9;

	set_dice_tcbInfo_measure(&tcbInfo, m);

	int dim = sizeof(tcbInfo);
	byte buf[dim];
	print_uart_int(dim_cert);
	print_uart("\r\n");

	if (verify_hw(ms2xl_eddsa, pub_key_platform_provider, (void *)DRAM_BASE, sanctum_sm_size, sd_sm_signature, 0) == 0)
	{
		print_uart("Error in HW SM signature verification!\r\n");
		goto verfication_error;
	}

	print_uart("\nKernel signature verification\r\n");
	print_uart("\r\n-----------------------------------------------------------\r\n");

	if (verify_hw(ms2xl_eddsa, pub_key_platform_provider, ((void *)DRAM_BASE) + sanctum_sm_size, sd_payload_size - sanctum_sm_size, sd_kernel_signature, 0) == 0)
	{
		print_uart("Error in HW kernel signature verification!\r\n");
		goto verfication_error;
	}


	ed25519_create_keypair(sanctum_device_root_key_pub, sanctum_device_root_key_priv, out_puf_1);

	sha3_init(&hash_ctx, 64);
	sha3_update(&hash_ctx, out_puf_1, 32);
	sha3_update(&hash_ctx, sanctum_sm_hash, 64);
	sha3_final(sanctum_CDI, &hash_ctx);

	unsigned char seed_for_ECA_keys[64];

	sha3_init(&hash_ctx, 64);
	sha3_update(&hash_ctx, sanctum_CDI, 64);
	sha3_update(&hash_ctx, sanctum_sm_hash, 64);
	sha3_final(seed_for_ECA_keys, &hash_ctx);
	ed25519_create_keypair(sanctum_ECASM_pk, sanctum_ECASM_priv, seed_for_ECA_keys);

	mbedtls_x509write_cert cert;
	mbedtls_x509write_crt_init(&cert);

	// Setting the name of the issuer of the cert
	int ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert, "CN=Root of Trust");
	if (ret != 0)
	{
		goto verfication_error;
	}

	// Setting the name of the subject of the cert
	ret = mbedtls_x509write_crt_set_subject_name_mod(&cert, "CN=Security Monitor");
	if (ret != 0)
	{
		goto verfication_error;
	}

	mbedtls_pk_context subj_key;
	mbedtls_pk_init(&subj_key);

	mbedtls_pk_context issu_key;
	mbedtls_pk_init(&issu_key);

	ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_device_root_key_priv, 64, 1);
	if (ret != 0)
	{
		goto verfication_error;
	}

	ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_device_root_key_pub, 32, 0);
	if (ret != 0)
	{
		goto verfication_error;
	}

	ret = mbedtls_pk_parse_public_key(&subj_key, sanctum_ECASM_pk, 32, 0);
	if (ret != 0)
	{
		goto verfication_error;
	}

	unsigned char serial[] = {0x01};
	mbedtls_x509write_crt_set_subject_key(&cert, &subj_key);
	mbedtls_x509write_crt_set_issuer_key(&cert, &issu_key);
	mbedtls_x509write_crt_set_serial_raw(&cert, serial, 1);
	mbedtls_x509write_crt_set_md_alg(&cert, KEYSTONE_SHA3);

	mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN);
	ret = mbedtls_x509write_crt_set_validity(&cert, "20230101000000", "20250101000000");
	if (ret != 0)
	{
		goto verfication_error;
	}

	mbedtls_x509write_crt_set_basic_constraints(&cert, 1, 10);

	if (mbedtls_x509write_crt_set_dice_tcbInfo(&cert, tcbInfo, dim, buf, sizeof(buf)) != 0)
		goto verfication_error;

	unsigned char cert_der[1024];
	int effe_len_cert_der;

	ret = mbedtls_x509write_crt_der_board(&cert, cert_der, 1024, NULL, NULL, out_puf_1);
	if (ret != 0)
	{
		effe_len_cert_der = ret;
		print_uart("ECA cert dimension: ");
		print_uart_int(effe_len_cert_der);
		print_uart("\r\n");
	}
	else
	{
		print_uart("Setting problems!\r\n");
		goto verfication_error;
	}

	unsigned char *cert_real = cert_der;
	int dif = 1024 - effe_len_cert_der;
	cert_real += dif;

	sanctum_length_cert = effe_len_cert_der;

	memcpy(&dim_cert, mem_addr_drk_len, 4);

	memcpy(certDRK, mem_addr_drk, dim_cert);

	memcpy(sanctum_cert_root, certDRK, sanctum_length_cert_root);
	memcpy(sanctum_cert_sm, cert_real, effe_len_cert_der);

	memset((void *)sanctum_ECASM_priv, 0, sizeof(*sanctum_ECASM_priv));
	memset((void *)sanctum_device_root_key_priv, 0, sizeof(*sanctum_device_root_key_priv));

	memset((void *)sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));
	memset((void *)sanctum_sm_public_key, 0, sizeof(*sanctum_sm_public_key));
	memset((void *)sanctum_sm_secret_key, 0, sizeof(*sanctum_sm_secret_key));
	memset((void *)sanctum_sm_signature, 0, sizeof(*sanctum_sm_signature));

	// print_uart("\r\nSM certificate:");
	// print_uart_int(sanctum_length_cert);
	// print_uart("\r\n");
	// for (int i = 0; i < sanctum_length_cert; i++)
	// 	print_uart_byte(sanctum_cert_sm[i]);
	// print_uart("\r\n-----------------------------------------------------------\r\n");

	// print_uart("\r\nDRK certificate:");
	// print_uart_int(sanctum_length_cert_root);
	// print_uart("\r\n");
	// for (int i = 0; i < sanctum_length_cert_root; i++)
	// 	print_uart_byte(sanctum_cert_root[i]);
	// print_uart("\r\n-----------------------------------------------------------\r\n");

	closeMMIOWindow(&ms2xl_eddsa);
	closeMMIOWindow(&ms2xl_puf_1);
	closeMMIOWindow(&ms2xl_sha3_512);

	print_uart("Bootloader operations finished, jump to SM level!\r\n");
	print_uart("\r\n-----------------------------------------------------------\r\n");

	if (res == 0)
	{
		// jump to the address
		__asm__ volatile(
			"li s0, 0x80000000;"
			"la a1, _dtb;"
			"jr s0");
	}
	while (1)
	{
		// do nothing
	}

verfication_error:
	if (res == 0)
	{
		print_uart("Verification failed, boot stopped\r\n");
	}
	while (1)
	{
	}
}
