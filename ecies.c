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
"MIIBAAIBADAQBgcqhkjOPQIBBgUrgQQAJwSB6DCB5QIBAQRIArxG5w0ydYPXKOh8\n" \
"NDD78GSW3yioDSf6a/nVmrLU7uokoqHGh8DhZczsed7PIen1sjJSRFQvpTfXzW6g\n" \
"yvBTiQHmRxmwWgx8oYGVA4GSAAQFFd9vDBbNrTpj4fqijc/r0SsjNsux05RlH35k\n" \
"4iKmOScufwf3qjLdQwlRVb2gxU9xqyf5zzye4cRypgWxuEmMb0/vy/bdvMkGS7HS\n" \
"Tl7dD4tWKGhGAB4oV2roBC6B5tTLFzpQL+SjqabQDjwCIrw9rhsoR5UTrcikJioa\n" \
"nzwv/wzEUsNPrLSUfMq1dYvt3hk=\n" \
"-----END PRIVATE KEY-----\n";

void RAND_init(void) {
	char buf[32];
	FILE *fin = fopen("/dev/random","rb");
	fread(buf, sizeof(buf), 1, fin);
	fclose(fin);
	RAND_seed(fin, 32);
}

EC_POINT *EC_POINT_mult_BN(const EC_GROUP *group, EC_POINT *P, const EC_POINT *a, const BIGNUM *b, BN_CTX *ctx)
{
	EC_POINT *O = EC_POINT_new(group);
	if (P == NULL) P = EC_POINT_new(group);

	for(int i = BN_num_bits(b); i >= 0; i--) {
		EC_POINT_dbl(group, P, P, ctx);
		if (BN_is_bit_set(b, i))
			EC_POINT_add(group, P, P, a, ctx);
		else
			EC_POINT_add(group, P, P, O, ctx);
	}

	return P;
}

int EC_KEY_public_derive_S(const EC_KEY *key, point_conversion_form_t fmt, BIGNUM *S, BIGNUM *R)
{
	BN_CTX *ctx = BN_CTX_new();
	const EC_GROUP *group = EC_KEY_get0_group(key);
	const EC_POINT *Kb = EC_KEY_get0_public_key(key);
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
	P = EC_POINT_mult_BN(group, P, Kb, r, ctx);
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

int EC_KEY_private_derive_S(const EC_KEY *key, const BIGNUM *R, BIGNUM *S)
{
	int ret = -1;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *Py = BN_new();
	const EC_GROUP *group = EC_KEY_get0_group(key);
	EC_POINT *Rp = EC_POINT_bn2point(group, R, NULL, ctx);
	const BIGNUM *kB = EC_KEY_get0_private_key(key);
	EC_GROUP_get_order(group, n, ctx);
	/* Calculate S = Px, P = (Px, Py) = R kB */
	EC_POINT *P = EC_POINT_mult_BN(group, NULL, Rp, kB, ctx);
	if (!EC_POINT_is_at_infinity(group, P)) {
		EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
		ret = 0;
	}
	BN_free(n);
	BN_free(Py);
	EC_POINT_free(Rp);
	EC_POINT_free(P);
	BN_CTX_free(ctx);
	return ret;
}

int decipher(const EC_KEY *key,
	const unsigned char *R_in, size_t R_len, const unsigned char *c_in, size_t c_len, 
	const unsigned char *d_in, size_t d_len, const unsigned char *salt, size_t salt_len)
{
	BIGNUM *R = BN_bin2bn(R_in, R_len, BN_new());
	BIGNUM *S = BN_new();

	if (EC_KEY_private_derive_S(key, R, S) != 0) {
		printf("Key derivation failed\n");
		return -1;
	}

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

        PKCS5_PBKDF2_HMAC((const char*)password, S_len, salt, salt_len, 2000, md, ke_len+km_len, ke_km);

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

int encipher(const EC_KEY *key,
	unsigned char *R_out, size_t *R_len, unsigned char *c_out, size_t *c_len,
	unsigned char *d_out, size_t *d_len, const unsigned char *salt, size_t salt_len)
{
	BIGNUM *R = BN_new();
	BIGNUM *S = BN_new();

	/* make sure it's not at infinity */
	while(EC_KEY_public_derive_S(key, POINT_CONVERSION_COMPRESSED, S, R) != 0);

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
	*c_len = 0;
	int outl = 0;

	PKCS5_PBKDF2_HMAC((const char*)password, S_len, salt, salt_len, 2000, md, ke_len+km_len, ke_km);

	EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
	EVP_EncryptUpdate(ectx, c_out + *c_len, &outl, (const unsigned char*)"super secret message", 20);
	*c_len += outl;
	EVP_EncryptFinal_ex(ectx, c_out + *c_len, &outl);
	*c_len += outl;

	unsigned int len;

	/* calculate MAC */
	HMAC(md, ke_km + ke_len, km_len, c_out, *c_len, d_out, &len);

	*d_len = len;

	/* then reverse operation */
	*R_len = BN_num_bytes(R);
	BN_bn2bin(R, R_out);

	return 0;
}

int main(void) {
	unsigned char R[512], D[512], c[512], salt[16];
	size_t R_len, D_len, c_len;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        RAND_init();

        BIO *b = BIO_new_mem_buf((void*)key, sizeof(key));
        EVP_PKEY *pkey = NULL;
        EC_KEY *eckey = NULL;

        PEM_read_bio_PrivateKey(b, &pkey, NULL, NULL);

        eckey = EVP_PKEY_get1_EC_KEY(pkey);

	RAND_bytes(salt, sizeof(salt));

	encipher(eckey, R, &R_len, c, &c_len, D, &D_len, salt, sizeof(salt));
	decipher(eckey, R, R_len, c, c_len, D, D_len, salt, sizeof(salt));

	return 0;
}
