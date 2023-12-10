 #include "ascon/ascon.h"
 #include "ascon/api.h"
 #include "ascon/round.h"
 #include "ascon/permutations.h"
 
 void ascon_adata(state_t* s, const uint8_t* ad, uint64_t adlen) {
  const int nr = (ASCON_RATE == 8) ? 6 : 8;
  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_RATE) {
      s->x0 = XOR(s->x0, LOAD(ad, 8));
      if (ASCON_RATE == 16) s->x1 = XOR(s->x1, LOAD(ad + 8, 8));
      P(s, nr);
      ad += ASCON_RATE;
      adlen -= ASCON_RATE;
    }
    /* final associated data block */
    word_t* px = &s->x0;
    if (ASCON_RATE == 16 && adlen >= 8) {
      s->x0 = XOR(s->x0, LOAD(ad, 8));
      px = &s->x1;
      ad += 8;
      adlen -= 8;
    }
    *px = XOR(*px, PAD(adlen));
    if (adlen) *px = XOR(*px, LOAD(ad, adlen));
    P(s, nr);
  }
  /* domain separation */
  s->x4 = XOR(s->x4, WORD_T(1));
  printstate("process associated data", s);
}

 void ascon_final(state_t* s, const uint8_t* k) {
  /* load key */
  word_t K0, K1, K2;
  ascon_loadkey(&K0, &K1, &K2, k);
  /* finalize */
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 8) {
    s->x1 = XOR(s->x1, K1);
    s->x2 = XOR(s->x2, K2);
  }
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 16) {
    s->x2 = XOR(s->x2, K1);
    s->x3 = XOR(s->x3, K2);
  }
  if (CRYPTO_KEYBYTES == 20) {
    s->x1 = XOR(s->x1, KEYROT(K0, K1));
    s->x2 = XOR(s->x2, KEYROT(K1, K2));
    s->x3 = XOR(s->x3, KEYROT(K2, WORD_T(0)));
  }
  P(s, 12);
  s->x3 = XOR(s->x3, K1);
  s->x4 = XOR(s->x4, K2);
  printstate("finalization", s);
}

 void ascon_init(state_t* s, const uint8_t* npub, const uint8_t* k) {
  /* load nonce */
  word_t N0 = LOAD(npub, 8);
  word_t N1 = LOAD(npub + 8, 8);
  /* load key */
  word_t K0, K1, K2;
  ascon_loadkey(&K0, &K1, &K2, k);
  /* initialize */
  PINIT(s);
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 8)
    s->x0 = XOR(s->x0, ASCON_128_IV);
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 16)
    s->x0 = XOR(s->x0, ASCON_128A_IV);
  if (CRYPTO_KEYBYTES == 20) s->x0 = XOR(s->x0, ASCON_80PQ_IV);
  if (CRYPTO_KEYBYTES == 20) s->x0 = XOR(s->x0, K0);
  s->x1 = XOR(s->x1, K1);
  s->x2 = XOR(s->x2, K2);
  s->x3 = XOR(s->x3, N0);
  s->x4 = XOR(s->x4, N1);
  P(s, 12);
  if (CRYPTO_KEYBYTES == 20) s->x2 = XOR(s->x2, K0);
  s->x3 = XOR(s->x3, K1);
  s->x4 = XOR(s->x4, K2);
  printstate("initialization", s);
}

 void ascon_loadkey(word_t* K0, word_t* K1, word_t* K2,
                               const uint8_t* k) {
  KINIT(K0, K1, K2);
  if (CRYPTO_KEYBYTES == 20) {
    *K0 = XOR(*K0, KEYROT(WORD_T(0), LOAD(k, 4)));
    k += 4;
  }
  *K1 = XOR(*K1, LOAD(k, 8));
  *K2 = XOR(*K2, LOAD(k + 8, 8));
}
