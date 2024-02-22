void init_sha3(void **ctx);
void sha3_256(void *ctx, unsigned char *input, unsigned char **out);
void printHash(unsigned char *hash);
void printHash_bin(unsigned char *hash_bin);
unsigned char* hash_to_string(unsigned char *hash);