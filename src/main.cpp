#include <Arduino.h>

// put function declarations here:
#include "max6675.h"
#include <WiFi.h>
#include "PubSubClient.h"
#include <NTPClient.h>
#include "ascon/api.h"
#include "ascon/ascon.h"
#include "ascon/crypto_aead.h"
#include "ascon/permutations.h"
#include "ascon/printstate.h"
#include <stdio.h>
#define CRYPTO_BYTES 64

int thermoDO = 4;
int thermoCS = 5;
int thermoCLK = 6;

char stemp[10];
float temp;
char strTimeStamp[20];

// WiFi 
const char *ssid = "Fibertel WiFi367 2.4GHz"; // Nombre WiFi
const char *password = "0141200866";  // Contraseña del WiFi

//const char *ssid = "Moto G (5) Plus 6864";
//const char *password = "manuel123";

// MQTT Broker
const char *mqtt_broker = "192.168.0.248";
//const char *mqtt_broker = "192.168.255.99";
const char *topic = "mosquitto/esp32";
//const char *mqtt_username = "";
//const char *mqtt_password = "";
const int mqtt_port = 1883;

void callback(char *topic, byte *payload, unsigned int length);

WiFiClient espClient;
PubSubClient client(espClient);
WiFiUDP ntpUDP; // UDP client
NTPClient timeClient(ntpUDP); // NTP client
static unsigned long long mlen;
static unsigned long long clen;

static unsigned char plaintext[CRYPTO_BYTES];
static unsigned char cipher[CRYPTO_BYTES]; 
static unsigned char npub[CRYPTO_NPUBBYTES]="";
static unsigned char ad[CRYPTO_ABYTES]="";
static unsigned char nsec[CRYPTO_ABYTES]="";

static unsigned char key[CRYPTO_KEYBYTES];
 
static char pl[CRYPTO_BYTES]="";
static char chex[CRYPTO_BYTES]="";
static char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
static char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
static char add[CRYPTO_ABYTES]="";
static char stringToSendToMosquitto[500];
static char strAux[100];

MAX6675 thermocouple(thermoCLK, thermoCS, thermoDO);


void setup() {

    // Se setea el baudrate a 9600;
    Serial.begin(9600);    
  
    Serial.println("MAX6675 test");
    // espera a que el MAX6675 se estabilice
    delay(500);

    // Conexion con la red WiFi
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.println("Connecting to WiFi network..");
    }
    
    Serial.println("Connected to WiFi network");
    // Conexión con el broker MQTT
    client.setServer(mqtt_broker, mqtt_port);
    client.setCallback(callback);

    timeClient.begin(); // init NTP
    timeClient.setTimeOffset(-10800); // 0= GMT, 3600 = GMT+1
    
    while (!client.connected()) {
        String client_id = "esp32-client-";
        client_id += String(WiFi.macAddress());
        Serial.printf("The client %s is connecting to broker MQTT\n", client_id.c_str());
        if (client.connect(client_id.c_str())) {
            Serial.println("Broker Mosquitto MQTT connected");
        } else {
            Serial.print("failed with state ");
            Serial.print(client.state());
            delay(2000);
        }
    }
    
    // Publicación y suscripción
    client.subscribe(topic);

}

void loop() {
  
  //Obtener hora de Argentina 

  if(!timeClient.update()) 
  {
    timeClient.forceUpdate();
  }

  String timestamp = timeClient.getFormattedTime();
  
  int i;
  for(i = 0; i < timestamp.length(); i++) {
      strTimeStamp[i] = timestamp[i];
  }
  strTimeStamp[i] = '\0';
  
  //Se guarda la temperatura en grados celsius
  temp = thermocouple.readCelsius();
  
  dtostrf(temp, 4, 2, stemp); //Convierte el float a una cadena

  strcat(stemp, " °C");
  strcat(plaintext, strTimeStamp);
  strcat(plaintext, " , ");
  strcat(plaintext, stemp);

  //sprintf(plaintext, "%s , %s °C", timestamp, stemp);

  crypto_aead_encrypt(cipher,&clen,plaintext,strlen(plaintext),ad,strlen(ad),nsec,npub,key);
  
  //Se convierte cipher a hexa y se guarda en chex
  string2hexString(cipher,clen,chex);

  sprintf(stringToSendToMosquitto,"%s",chex);
  sprintf(strAux, "Message plaintext: %s\n", plaintext);
  Serial.print(strAux);

  client.publish(topic, stringToSendToMosquitto);
  client.loop();
  
  plaintext[0] = '\0';
  // Para que se actualicen los datos del MAX6675 se necesita un delay minimo de 250ms
  delay(5000);
}


void callback(char *topic, byte *payload, unsigned int length) {
    Serial.print("Message arrived in topic: ");
    Serial.println(topic);
    Serial.print("Message encrypted:");
    for (int i = 0; i < length; i++) {
        Serial.print((char) payload[i]);
    }
    Serial.println();
    Serial.println("-----------------------");
}

forceinline void ascon_loadkey(word_t* K0, word_t* K1, word_t* K2,
                               const uint8_t* k) {
  KINIT(K0, K1, K2);
  if (CRYPTO_KEYBYTES == 20) {
    *K0 = XOR(*K0, KEYROT(WORD_T(0), LOAD(k, 4)));
    k += 4;
  }
  *K1 = XOR(*K1, LOAD(k, 8));
  *K2 = XOR(*K2, LOAD(k + 8, 8));
}

forceinline void ascon_init(state_t* s, const uint8_t* npub, const uint8_t* k) {
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

forceinline void ascon_adata(state_t* s, const uint8_t* ad, uint64_t adlen) {
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

forceinline void ascon_encrypt(state_t* s, uint8_t* c, const uint8_t* m,
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

forceinline void ascon_decrypt(state_t* s, uint8_t* m, const uint8_t* c,
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

forceinline void ascon_final(state_t* s, const uint8_t* k) {
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
void *hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02x", &bytearray[i]);
    }
}
