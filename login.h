#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <jansson.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

typedef struct Datos_crudos
{
    json_t *Salt;
    json_t *UserName;
    json_t *Hash;
}datos_crudos;

typedef struct Datos
{
    const char *Salt_hex;
    const char *UserName;
    const char *Hash_hex;
}datos;

void limpiar_pantalla();
void continuar();
void calcular_hash(unsigned char *Password, unsigned char *Salt_bin, unsigned char *Hash_bin);
void crear_usuario();
void verificar_usuario();
datos_crudos obtener_datos_crudos(json_t *infoUser);
datos obtener_datos(datos_crudos usuario);
int comprobar_password(const char *SaltInfo_hex, const char *HashInfo_hex);
int iniciar_sesion();
