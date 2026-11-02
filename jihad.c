/* Jihad Cipher */
/* KryptoMagick (Karl Zander) */
uint32_t CON[4] = {0x00010203, 0x23456789, 0xabcdef00, 0xdefabecc};

struct jihad_state {
    uint32_t S[8];
    uint8_t O;
};

uint32_t rotl(uint32_t v, int r) {
    return (v << r) | (v >> (32 - r));
}

void key_setup(struct jihad_state *ctx, uint8_t *key, uint8_t *nonce) {
    ctx->S[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    ctx->S[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    ctx->S[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    ctx->S[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    ctx->S[4] = (key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19];
    ctx->S[5] = (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    ctx->S[6] = (key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27];
    ctx->S[7] = (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];
    
    ctx->S[4] ^= (nonce[0] << 24) + (nonce[1] << 16) + (nonce[2] << 8) + nonce[3];
    ctx->S[5] ^= (nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7];
    ctx->S[6] ^= (nonce[8] << 24) + (nonce[9] << 16) + (nonce[10] << 8) + nonce[11];
    ctx->S[7] ^= (nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15];
    
    ctx->S[1] ^= CON[0];
    ctx->S[3] ^= CON[1];
    ctx->S[5] ^= CON[2];
    ctx->S[7] ^= CON[3];
}
   
void update(struct jihad_state *ctx) {
    ctx->S[1] ^= rotl(ctx->S[0] + ctx->S[7], 3);
    ctx->S[7] ^= rotl(ctx->S[4] + ctx->S[6], 6);
    ctx->S[5] ^= rotl(ctx->S[3] + ctx->S[5], 10);
    ctx->S[2] ^= rotl(ctx->S[6] + ctx->S[4], 15);
    ctx->S[6] ^= rotl(ctx->S[2] + ctx->S[3], 21);
    ctx->S[3] ^= rotl(ctx->S[5] + ctx->S[2], 28);
    ctx->S[0] ^= rotl(ctx->S[7] + ctx->S[1], 1);
    ctx->S[4] ^= rotl(ctx->S[1] + ctx->S[0], 7);
    
    ctx->O = ctx->S[0] ^ ctx->S[1] ^ ctx->S[2] ^ ctx->S[3] ^ ctx->S[4] ^ ctx->S[5] ^ ctx->S[6] ^ ctx->S[7];
}

uint8_t output(struct jihad_state *ctx, uint8_t in) {
    update(ctx);
    return ctx->O ^ in;
}
