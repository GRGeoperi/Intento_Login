#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <jansson.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#ifdef _WIN32
	#include <windows.h>
#endif

typedef struct DatosInutiles
{
    json_t *Salt;
    json_t *UserName;
    json_t *Hash;
}datosInutiles;

typedef struct DatosUtiles
{
    const char *Salt_hex;
    const char *UserName;
    const char *Hash_hex;
}datosUtiles;

void ClearScreen();
void Continue();
void CalculateHash(unsigned char *Password, unsigned char *Salt_bin, unsigned char *Hash_bin);
void CreacionUsuarios();
void VerificacionUsuarios();
datosInutiles bloqueInutil(json_t *infoUser);
datosUtiles bloqueUtil(datosInutiles usuario);
int PasswordCheck(const char *SaltInfo_hex, const char *HashInfo_hex);
int LogUser();
