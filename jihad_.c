/* Jihad Cipher */
/* KryptoMagick (Karl Zander) */
uint32_t CON[4] = {0x00010203, 0x23456789, 0xabcdef00, 0xdefabecc};

struct jihad_state {
    uint32_t S[8];
    uint32_t O[8];    uint8_t O;
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
    
    ctx->S[1] ^= 0;
    ctx->S[3] ^= CON[2];
    ctx->S[5] ^= 0;
    ctx->S[7] ^= CON[3];
}
   
void update(struct jihad_state *ctx) {
    ctx->O[1] ^= rotl(ctx->O[1], 1) + ctx->O[4];
    ctx->O[13] ^= rotl(ctx->O[13], 3) + ctx->O[1];
    ctx->O[11] ^= rotl(ctx->O[11], 6) + ctx->O[13];
    ctx->O[7] ^= rotl(ctx->O[7], 10) + ctx->O[11];
    ctx->O[5] ^= rotl(ctx->O[5], 15) + ctx->O[7];
    ctx->O[2] ^= rotl(ctx->O[2], 21) + ctx->O[5];
    ctx->O[15] ^= rotl(ctx->O[15], 28) + ctx->O[2];
    ctx->O[10] ^= rotl(ctx->O[10], 7) + ctx->O[15];
    ctx->O[6] ^= rotl(ctx->O[6], 11) + ctx->O[10];
    ctx->O[3] ^= rotl(ctx->O[3], 13) + ctx->O[6];
    ctx->O[14] ^= rotl(ctx->O[14], 17) + ctx->O[3];
    ctx->O[12] ^= rotl(ctx->O[12], 19) + ctx->O[14];
    ctx->O[9] ^= rotl(ctx->O[9], 23) + ctx->O[12];
    ctx->O[8] ^= rotl(ctx->O[8], 29) + ctx->O[9];
    ctx->O[0] ^= rotl(ctx->O[0], 31) + ctx->O[8];
    ctx->O[4] ^= rotl(ctx->O[4], 5) + ctx->O[0];
    
 
}

void load_state(struct jihad_state *ctx) {
    memcpy(ctx->O, ctx->S, 8*sizeof(uint32_t));
}

void rounds(struct jihad_state *ctx, int rounds) {
    load_state(ctx);
    for (int r = 0; r < rounds; r++) {
        update(ctx);
    }
}

void output(struct jihad_state *ctx, uint8_t *in) {
    rounds(ctx, 16);
    
    in[0]  = (uint8_t)(ctx->O[0] >> 24);
    in[1]  = (uint8_t)(ctx->O[0] >> 16);
    in[2]  = (uint8_t)(ctx->O[0] >> 8);
    in[3]  = (uint8_t)(ctx->O[0]);
    
    in[4]  = (uint8_t)(ctx->O[1] >> 24);
    in[5]  = (uint8_t)(ctx->O[1] >> 16);
    in[6]  = (uint8_t)(ctx->O[1] >> 8);
    in[7]  = (uint8_t)(ctx->O[1]);
    
    in[8]  = (uint8_t)(ctx->O[2] >> 24);
    in[9]  = (uint8_t)(ctx->O[2] >> 16);
    in[10] = (uint8_t)(ctx->O[2] >> 8);
    in[11] = (uint8_t)(ctx->O[2]);
    
    in[12] = (uint8_t)(ctx->O[3] >> 24);
    in[13] = (uint8_t)(ctx->O[3] >> 16);
    in[14] = (uint8_t)(ctx->O[3] >> 8);
    in[15] = (uint8_t)(ctx->O[3]);
    
    in[16] = (uint8_t)(ctx->O[4] >> 24);
    in[17] = (uint8_t)(ctx->O[4] >> 16);
    in[18] = (uint8_t)(ctx->O[4] >> 8);
    in[19] = (uint8_t)(ctx->O[4]);
    
    in[20] = (uint8_t)(ctx->O[5] >> 24);
    in[21] = (uint8_t)(ctx->O[5] >> 16);
    in[22] = (uint8_t)(ctx->O[5] >> 8);
    in[23] = (uint8_t)(ctx->O[5]);
    
    in[24] = (uint8_t)(ctx->O[6] >> 24);
    in[25] = (uint8_t)(ctx->O[6] >> 16);
    in[26] = (uint8_t)(ctx->O[6] >> 8);
    in[27] = (uint8_t)(ctx->O[6]);
    
    in[28] = (uint8_t)(ctx->O[7] >> 24);
    in[29] = (uint8_t)(ctx->O[7] >> 16);
    in[30] = (uint8_t)(ctx->O[7] >> 8);
    in[31] = (uint8_t)(ctx->O[7]);
    
    in[32] = (uint8_t)(ctx->O[8] >> 24);
    in[33] = (uint8_t)(ctx->O[8] >> 16);
    in[34] = (uint8_t)(ctx->O[8] >> 8);
    in[35] = (uint8_t)(ctx->O[8]);
    
    in[36] = (uint8_t)(ctx->O[9] >> 24);
    in[37] = (uint8_t)(ctx->O[9] >> 16);
    in[38] = (uint8_t)(ctx->O[9] >> 8);
    in[39] = (uint8_t)(ctx->O[9]);
    
    in[40] = (uint8_t)(ctx->O[10] >> 24);
    in[41] = (uint8_t)(ctx->O[10] >> 16);
    in[42] = (uint8_t)(ctx->O[10] >> 8);
    in[43] = (uint8_t)(ctx->O[10]);
    
    in[44] = (uint8_t)(ctx->O[11] >> 24);
    in[45] = (uint8_t)(ctx->O[11] >> 16);
    in[46] = (uint8_t)(ctx->O[11] >> 8);
    in[47] = (uint8_t)(ctx->O[11]);
    
    in[48] = (uint8_t)(ctx->O[12] >> 24);
    in[49] = (uint8_t)(ctx->O[12] >> 16);
    in[50] = (uint8_t)(ctx->O[12] >> 8);
    in[51] = (uint8_t)(ctx->O[12]);
    
    in[52] = (uint8_t)(ctx->O[13] >> 24);
    in[53] = (uint8_t)(ctx->O[13] >> 16);
    in[54] = (uint8_t)(ctx->O[13] >> 8);
    in[55] = (uint8_t)(ctx->O[13]);
    
    in[56] = (uint8_t)(ctx->O[14] >> 24);
    in[57] = (uint8_t)(ctx->O[14] >> 16);
    in[58] = (uint8_t)(ctx->O[14] >> 8);
    in[59] = (uint8_t)(ctx->O[14]);
    
    in[60] = (uint8_t)(ctx->O[15] >> 24);
    in[61] = (uint8_t)(ctx->O[15] >> 16);
    in[62] = (uint8_t)(ctx->O[15] >> 8);
    in[63] = (uint8_t)(ctx->O[15]);
}
