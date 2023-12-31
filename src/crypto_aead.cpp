#include "ascon/crypto_aead.h"
#include "ascon/ascon.h"
#include "ascon/api.h"
#include "ascon/permutations.h"
#include "ascon/printstate.h"
#include <stdio.h>
#include <string.h>

void ascon_encrypt(state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen) {
  const int nr = (ASCON_RATE == 8) ? 6 : 8;
  /* full plaintext blocks */
  while (mlen >= ASCON_RATE) {
    s->x0 = XOR(s->x0, LOAD(m, 8));
    STORE(c, s->x0, 8);
    if (ASCON_RATE == 16) {
      s->x1 = XOR(s->x1, LOAD(m + 8, 8));
      STORE(c + 8, s->x1, 8);
    }
    P(s, nr);
    m += ASCON_RATE;
    c += ASCON_RATE;
    mlen -= ASCON_RATE;
  }
  /* final plaintext block */
  word_t* px = &s->x0;
  if (ASCON_RATE == 16 && mlen >= 8) {
    s->x0 = XOR(s->x0, LOAD(m, 8));
    STORE(c, s->x0, 8);
    px = &s->x1;
    m += 8;
    c += 8;
    mlen -= 8;
  }
  *px = XOR(*px, PAD(mlen));
  if (mlen) {
    *px = XOR(*px, LOAD(m, mlen));
    STORE(c, *px, mlen);
  }
  printstate("process plaintext", s);
}

 void ascon_decrypt(state_t* s, uint8_t* m, const uint8_t* c,
                               uint64_t clen) {
  const int nr = (ASCON_RATE == 8) ? 6 : 8;
  /* full ciphertext blocks */
  while (clen >= ASCON_RATE) {
    word_t cx = LOAD(c, 8);
    s->x0 = XOR(s->x0, cx);
    STORE(m, s->x0, 8);
    s->x0 = cx;
    if (ASCON_RATE == 16) {
      cx = LOAD(c + 8, 8);
      s->x1 = XOR(s->x1, cx);
      STORE(m + 8, s->x1, 8);
      s->x1 = cx;
    }
    P(s, nr);
    m += ASCON_RATE;
    c += ASCON_RATE;
    clen -= ASCON_RATE;
  }
  /* final ciphertext block */
  word_t* px = &s->x0;
  if (ASCON_RATE == 16 && clen >= 8) {
    word_t cx = LOAD(c, 8);
    s->x0 = XOR(s->x0, cx);
    STORE(m, s->x0, 8);
    s->x0 = cx;
    px = &s->x1;
    m += 8;
    c += 8;
    clen -= 8;
  }
  *px = XOR(*px, PAD(clen));
  if (clen) {
    word_t cx = LOAD(c, clen);
    *px = XOR(*px, cx);
    STORE(m, *px, clen);
    *px = CLEAR(*px, clen);
    *px = XOR(*px, cx);
  }
  printstate("process ciphertext", s);
}

void string2hexString(unsigned char* input, int clen, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    for (i=0;i<clen;i+=2){
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;

    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  state_t s;
  (void)nsec;
  *clen = mlen + CRYPTO_ABYTES;
  /* perform ascon computation */
  ascon_init(&s, npub, k);
  ascon_adata(&s, ad, adlen);
  ascon_encrypt(&s, c, m, mlen);
  ascon_final(&s, k);
  /* set tag */
  STOREBYTES(c + mlen, s.x3, 8);
  STOREBYTES(c + mlen + 8, s.x4, 8);
  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  state_t s;
  (void)nsec;
  if (clen < CRYPTO_ABYTES) return -1;
  *mlen = clen = clen - CRYPTO_ABYTES;
  /* perform ascon computation */
  ascon_init(&s, npub, k);
  ascon_adata(&s, ad, adlen);
  ascon_decrypt(&s, m, c, clen);
  ascon_final(&s, k);
  /* verify tag (should be constant time, check compiler output) */
  s.x3 = XOR(s.x3, LOADBYTES(c + clen, 8));
  s.x4 = XOR(s.x4, LOADBYTES(c + clen + 8, 8));
  return NOTZERO(s.x3, s.x4);
}

void hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02x", &bytearray[i]);
    }
}