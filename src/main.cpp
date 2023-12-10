//=====[Libraries]=============================================================
#include <Arduino.h>
#include "max6675.h"
#include <WiFi.h>
#include "PubSubClient.h"
#include <NTPClient.h>
#include "ascon/crypto_aead.h"
#include "ascon/api.h"
#include <stdio.h>

//=====[Declaration of private defines]========================================
#define CRYPTO_BYTES 64

//=====[Declaration and initialization of private global variables]============
//=====[ASCON]====================================
static unsigned long long mlen;
static unsigned long long clen;

static unsigned char plaintext[CRYPTO_BYTES];
static unsigned char cipher[CRYPTO_BYTES]; 
static unsigned char npub[CRYPTO_NPUBBYTES]="";
static unsigned char ad[CRYPTO_ABYTES]="";
static unsigned char nsec[CRYPTO_ABYTES]="";

static unsigned char key[CRYPTO_KEYBYTES];
static char chex[CRYPTO_BYTES]="";
static char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
static char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
static char add[CRYPTO_ABYTES]="";

//=====[TEMPERATURE SENSOR]====================================
int thermoDO = 4;
int thermoCS = 5;
int thermoCLK = 6;
char stemp[10];
float temp;
char strTimeStamp[20];

//=====[WIFI AND MQTT BROKER]==================================== 
const char *ssid = "Fibertel WiFi367 2.4GHz"; // Nombre WiFi
const char *password = "0141200866";  // Contraseña del WiFi
//const char *ssid = "Moto G (5) Plus 6864";
//const char *password = "manuel123";

const char *mqtt_broker = "192.168.0.248"; // MQTT Broker
//const char *mqtt_broker = "192.168.255.99";
const char *topic = "mosquitto/esp32";  //MOSQUITTO Topic
const int mqtt_port = 1883; //MQTT Port
static char stringToSendToMosquitto[500];

//=====[AUXILIAR VARIABLES]=======================================
static char strAux[100];

//=====[Declaration and initialization of public global objects]===============
WiFiClient espClient;
PubSubClient client(espClient);
WiFiUDP ntpUDP; // UDP client
NTPClient timeClient(ntpUDP); // NTP client
MAX6675 thermocouple(thermoCLK, thermoCS, thermoDO);

//=====[Declarations (prototypes) of functions]========================
void callback(char *topic, byte *payload, unsigned int length);

//=====[MAIN PROGRAM]===================================================
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
  hextobyte(keyhex,key);
  hextobyte(nonce,npub);

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

//=====[Implementation of private functions]========================
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


