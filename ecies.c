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

struct ecies_ctx {
	BIGNUM *r;
	BIGNUM *R;
	BIGNUM *Px;
	BIGNUM *Py;
};

void RAND_init(void) {
	char buf[32];
	FILE *fin = fopen("/dev/random","rb");
	fread(buf, sizeof(buf), 1, fin);
	fclose(fin);
	RAND_seed(fin, 32);
}

int decipher(const EC_KEY *key,
	const unsigned char *R_in, size_t R_len, const unsigned char *c_in, size_t c_len, 
	const unsigned char *d_in, size_t d_len)
{
	BN_CTX *bnctx = BN_CTX_new();
	BIGNUM *kBR = BN_new();
	BIGNUM *Rbn = BN_new();
	BIGNUM *Px = BN_new();
	BIGNUM *Py = BN_new();
	BIGNUM *G = BN_new();
	const BIGNUM *kB = EC_KEY_get0_private_key(key);
	const EC_GROUP *grp = EC_KEY_get0_group(key);
	EC_GROUP_get_order(grp, G, bnctx);

	EC_POINT *P = EC_POINT_new(grp);
	EC_POINT *R = EC_POINT_new(grp);

        Rbn = BN_bin2bn(R_in, R_len, Rbn);
        ERR_print_errors_fp(stdout);

        EC_POINT_bn2point(grp, Rbn, R, bnctx);
        ERR_print_errors_fp(stdout);

	int bits = BN_num_bits(kB);
	/* then multiply */
        for(int i = bits-1; i>=0; i--) {
                EC_POINT_dbl(grp, P, P, bnctx);
                if (BN_is_bit_set(kB, i))
                        EC_POINT_add(grp, P, P, R, bnctx);
        }

	if (EC_POINT_is_at_infinity(grp, P)) {
		ERR_print_errors_fp(stdout);
		return 1;
	}

        EC_POINT_get_affine_coordinates_GF2m(grp, P, Px, Py, bnctx);

        printf("S = ");
        BN_print_fp(stdout, Px);
        printf("\n");

        size_t S_len = BN_num_bytes(Px);
        unsigned char password[S_len];
        BN_bn2bin(Px, password);

        /* then we can move on to traditional crypto using pbkdf2 we generate keys */
        const EVP_MD *md = EVP_sha1();
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
        size_t km_len = EVP_MD_block_size(md);
        unsigned char ke_km[ke_len+km_len];

        unsigned char dc_out[2048] = {0};
        size_t dc_len = 0;
        size_t outl = 0;

        PKCS5_PBKDF2_HMAC((const char*)password, S_len, "12345678", 8, 2000, md, ke_len+km_len, ke_km);

        /* hopefully we now have key data */
        for(size_t i = 0; i < ke_len+km_len; i+=2) {
                if (i % 16 == 0) printf("\n%04x: ", i);
                printf("%02x%02x ", ke_km[i], ke_km[i+1]);
        }
        printf("\n");

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
	struct ecies_ctx ctx;

	BN_CTX *bnctx = BN_CTX_new();
	BIGNUM *order = BN_new();

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
	int bits = 0;
	/* now we have public key */
	if (EC_GROUP_get_order(grp, order, bnctx) != 1) {
		printf("Failed\n");
		return 1;
	} else {
		bits = BN_num_bits(order);
	}

	ctx.r = BN_new();
	ctx.Px = BN_new();
	ctx.Py = BN_new();

	/* now we can generate r */ 
	BN_rand(ctx.r, bits, -1, 0);
	ctx.R = BN_new();
	const EC_POINT *R = EC_GROUP_get0_generator(grp);
	EC_POINT *Z = EC_POINT_new(grp);

	for(int i = bits-1; i >= 0; i--) {
		EC_POINT_dbl(grp, Z, Z, bnctx);
		if (BN_is_bit_set(ctx.r, i))
			EC_POINT_add(grp, Z, Z, R, bnctx);
	}

	EC_POINT_point2bn(grp, Z, POINT_CONVERSION_COMPRESSED, ctx.R, bnctx);

	printf("R = ");
	BN_print_fp(stdout, ctx.R);
	printf("\n");

	EC_POINT *tmp = EC_POINT_new(grp);

	/* then we multiply them */
	for(int i = bits-1; i >= 0; i--) {
		EC_POINT_dbl(grp, tmp, tmp, bnctx);
		if (BN_is_bit_set(ctx.r, i))
			EC_POINT_add(grp, tmp, tmp, pub, bnctx);
	}

	/* and check it's not at infinity */
	if (EC_POINT_is_at_infinity(grp, tmp)) {
		printf("Rejected\n");
		return 1;
	}

	/* GOOD, extract Px */
	EC_POINT_get_affine_coordinates_GF2m(grp, tmp, ctx.Px, ctx.Py, bnctx);

	printf("S = ");
	BN_print_fp(stdout, ctx.Px);
	printf("\n");

	size_t S_len = BN_num_bytes(ctx.Px);
	unsigned char password[S_len];
	BN_bn2bin(ctx.Px, password);

	/* then we can move on to traditional crypto using pbkdf2 we generate keys */
	const EVP_MD *md = EVP_sha1();
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
	size_t km_len = EVP_MD_block_size(md);
	unsigned char ke_km[ke_len+km_len];

	unsigned char c_out[2048];
	size_t c_len = 0;
	size_t outl = 0;

	PKCS5_PBKDF2_HMAC((const char*)password, S_len, "12345678", 8, 2000, md, ke_len+km_len, ke_km);

	/* hopefully we now have key data */
	for(size_t i = 0; i < ke_len+km_len; i+=2) {
		if (i % 16 == 0) printf("\n%04x: ", i);
		printf("%02x%02x ", ke_km[i], ke_km[i+1]);
	}
	printf("\n");

	EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
	EVP_EncryptUpdate(ectx, c_out + c_len, &outl, "super secret message", 20);
	c_len += outl;
	EVP_EncryptFinal_ex(ectx, c_out + c_len, &outl);
	c_len += outl;

	/* calculate MAC */
	unsigned char d_out[km_len];
	size_t d_len;
	HMAC(md, ke_km + ke_len, km_len, c_out, c_len, d_out, &d_len);

	/* then reverse operation */
	size_t R_len = BN_num_bytes(ctx.R);
	unsigned char R_out[R_len];
	BN_bn2bin(ctx.R, R_out);

	decipher(eckey, R_out, R_len, c_out, c_len, d_out, d_len);

	return 0;
}
