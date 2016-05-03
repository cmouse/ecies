#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>

const char key[] = \
"-----BEGIN PRIVATE KEY-----\n" \
"MFACAQAwEAYHKoZIzj0CAQYFK4EEAAQEOTA3AgEBBA69/41cvj8sXnrowXqhUKEi\n" \
"AyAABADcsXP3zhDGB6sd56MYYwFJsNoMbH5ps6NkcHh18g==\n" \
"-----END PRIVATE KEY-----";

void RAND_init(void) {
	char buf[32];
	FILE *fin = fopen("/dev/random","rb");
	fread(buf, sizeof(buf), 1, fin);
	fclose(fin);
	RAND_seed(fin, 32);
}

EC_POINT *EC_POINT_mult_BN(const EC_GROUP *group, EC_POINT *P, const EC_POINT *a, const BIGNUM *b, BN_CTX *ctx)
{
	EC_POINT *Z = EC_POINT_new(group);
	if (P == NULL) P = EC_POINT_new(group);

	for(int i = BN_num_bits(b); i >= 0; i--) {
		EC_POINT_dbl(group, P, P, ctx);
		if (BN_is_bit_set(b, i))
			EC_POINT_add(group, P, P, a, ctx);
		else
			EC_POINT_add(group, P, P, Z, ctx);
	}

	return P;
}

int EC_POINT_derive_S(const EC_GROUP *group, const EC_POINT *key, point_conversion_form_t fmt, BIGNUM *S, BIGNUM *R)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *r = BN_new();
	EC_POINT *P = NULL;
	EC_POINT *Rp = EC_POINT_new(group);
	BIGNUM *Py = BN_new();
	const EC_POINT *G = EC_GROUP_get0_generator(group);
	int bits,ret=-1;
	EC_GROUP_get_order(group, n, ctx);
	bits = BN_num_bits(n);
	BN_rand(r, bits, -1, 0);
	/* calculate R = rG */
	Rp = EC_POINT_mult_BN(group, Rp, G, r, ctx);
	/* calculate S = Px, P = (Px,Py) = Kb R */
	P = EC_POINT_mult_BN(group, P, key, r, ctx);
	if (!EC_POINT_is_at_infinity(group, P)) {
		EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
		EC_POINT_point2bn(group, Rp, fmt, R, ctx);
		ret = 0;
	}
	BN_free(r);
	BN_free(n);
	BN_free(Py);
	EC_POINT_free(P);
	EC_POINT_free(Rp);
	BN_CTX_free(ctx);
	return ret;
}

BIGNUM *EC_KEY_derive_S(const EC_KEY *key, const BIGNUM *R, BIGNUM *S)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *Py = BN_new();
	const EC_GROUP *group = EC_KEY_get0_group(key);
	EC_POINT *Rp = EC_POINT_bn2point(group, R, NULL, ctx);
	const BIGNUM *kB = EC_KEY_get0_private_key(key);
	if (S == NULL) S = BN_new();
	EC_GROUP_get_order(group, n, ctx);
	EC_POINT *P = EC_POINT_mult_BN(group, NULL, Rp, kB, ctx);
	if (!EC_POINT_is_at_infinity(group, P)) {
		EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
	}
	BN_free(n);
	BN_free(Py);
	EC_POINT_free(Rp);
	EC_POINT_free(P);
	BN_CTX_free(ctx);
	return S;
}

int decipher(const EC_KEY *key,
	const unsigned char *R_in, size_t R_len, const unsigned char *c_in, size_t c_len, 
	const unsigned char *d_in, size_t d_len)
{
	BIGNUM *R = BN_bin2bn(R_in, R_len, BN_new());
	BIGNUM *S = EC_KEY_derive_S(key, R, BN_new());

        printf("S_decipher = ");
        BN_print_fp(stdout, S);
        printf("\n");

        size_t S_len = BN_num_bytes(S);
        unsigned char password[S_len];
        BN_bn2bin(S, password);

        /* then we can move on to traditional crypto using pbkdf2 we generate keys */
        const EVP_MD *md = EVP_sha1();
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
        size_t km_len = EVP_MD_block_size(md);
        unsigned char ke_km[ke_len+km_len];

        unsigned char dc_out[2048] = {0};
        size_t dc_len = 0;
        int outl = 0;

        PKCS5_PBKDF2_HMAC((const char*)password, S_len, (const unsigned char*)"12345678", 8, 2000, md, ke_len+km_len, ke_km);

        unsigned char dv_out[km_len];
        unsigned int dv_len;
        HMAC(md, ke_km + ke_len, km_len, c_in, c_len, dv_out, &dv_len);

	if (d_len != dv_len || memcmp(dv_out, d_in, dv_len) != 0)
		printf("MAC verification failed\n");

        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
        EVP_DecryptUpdate(ectx, dc_out + dc_len, &outl, c_in, c_len);
        dc_len += outl;
        EVP_DecryptFinal_ex(ectx, dc_out + dc_len, &outl);
        dc_len += outl;
	dc_out[dc_len] = 0;
	printf("%s\n", dc_out);

	return 0;
}

int main(void) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	RAND_init();

	BIO *b = BIO_new_mem_buf((void*)key, sizeof(key));
	EVP_PKEY *pkey = NULL;
	EC_KEY *eckey = NULL;

	PEM_read_bio_PrivateKey(b, &pkey, NULL, NULL);

	eckey = EVP_PKEY_get1_EC_KEY(pkey);

	const EC_POINT *pub = EC_KEY_get0_public_key(eckey);
	const EC_GROUP *grp = EC_KEY_get0_group(eckey);

	BIGNUM *R = BN_new();
	BIGNUM *S = BN_new();

	EC_POINT_derive_S(grp, pub, POINT_CONVERSION_COMPRESSED, S, R);

	printf("R = ");
	BN_print_fp(stdout, R);
	printf("\n");

	printf("S_encipher = ");
	BN_print_fp(stdout, S);
	printf("\n");

	size_t S_len = BN_num_bytes(S);
	unsigned char password[S_len];
	BN_bn2bin(S, password);

	/* then we can move on to traditional crypto using pbkdf2 we generate keys */
	const EVP_MD *md = EVP_sha1();
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
	size_t km_len = EVP_MD_block_size(md);
	unsigned char ke_km[ke_len+km_len];

	unsigned char c_out[2048];
	size_t c_len = 0;
	int outl = 0;

	PKCS5_PBKDF2_HMAC((const char*)password, S_len, (const unsigned char*)"12345678", 8, 2000, md, ke_len+km_len, ke_km);

	EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
	EVP_EncryptUpdate(ectx, c_out + c_len, &outl, (const unsigned char*)"super secret message", 20);
	c_len += outl;
	EVP_EncryptFinal_ex(ectx, c_out + c_len, &outl);
	c_len += outl;

	/* calculate MAC */
	unsigned char d_out[km_len];
	unsigned int d_len;
	HMAC(md, ke_km + ke_len, km_len, c_out, c_len, d_out, &d_len);

	/* then reverse operation */
	size_t R_len = BN_num_bytes(R);
	unsigned char R_out[R_len];
	BN_bn2bin(R, R_out);

	decipher(eckey, R_out, R_len, c_out, c_len, d_out, d_len);

	return 0;
}
