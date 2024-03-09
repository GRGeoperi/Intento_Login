#include "login.h"

void limpiar_pantalla()
{
    system("clear");
}
void continuar()
{
    printf("Presione enter para continuar...\n");
    getchar();
}

void calcular_hash(unsigned char *Password, unsigned char *Salt_bin, unsigned char *Hash_bin)
{
    // Longitud del hash
    unsigned int digest_len;
    // Contexto de digestión
    EVP_MD_CTX *infoContext = EVP_MD_CTX_new();
    // Inicializa el hasheo usando SHA256
    EVP_DigestInit_ex(infoContext, EVP_sha256(), NULL);
    // Actualiza el hasheo de la contraseña
    EVP_DigestUpdate(infoContext, Password, strlen(Password));
    // Actualiza el hasheo usando la sal
    EVP_DigestUpdate(infoContext, Salt_bin, 8);
    // Finaliza el hasheo y se obtiene el hash resultante
    EVP_DigestFinal_ex(infoContext, Hash_bin, &digest_len);
    // Limpia la estructura de digestión
    EVP_MD_CTX_destroy(infoContext);
}

void crear_usuario()
{
    // El objeto principal del archivo JSON
    json_t *bloqueGeneral = json_object();
    // El objeto de administrador del archivo JSON
    json_t *bloqueRoot = json_object();
    // Se agrega al objeto principal
    json_object_set_new(bloqueGeneral, "administrador", bloqueRoot);
    // Semilla para el administrador
    unsigned char saltRoot_bin[8];
    RAND_bytes(saltRoot_bin, 8);
    // Semilla hexadecimal del administrador
    char saltRoot_hex[8 * 2 + 1];
    EVP_EncodeBlock((unsigned char *)saltRoot_hex, saltRoot_bin, 8);
    // Adición de cada una de las semillas en hexadecimal al archivo JSON
    json_object_set_new(bloqueRoot, "salt", json_string(saltRoot_hex));
    // Usuario con privilegios de administrador
    char root[256];
    printf("Administrador: ");
    fflush(stdout);
    scanf("%255s%*c", root);
    // (Inseguro) contraseña directa del administrador
    char root_password[256];
    printf("Contraseña: ");
    fflush(stdout);
    scanf("%255s%*c", root_password);
    limpiar_pantalla();
    continuar();
    // Adición del usuario al archivo JSON
    json_object_set_new(bloqueRoot, "usuario", json_string(root));
    // Hasheo de la contraseña del usuario usando el algoritmo SHA256
    unsigned char rootHash_bin[32];
    calcular_hash(root_password, saltRoot_bin, rootHash_bin);
    // Conversión del hash a hexadecimal
    char rootHash_hex[32 * 2 + 1];
    EVP_EncodeBlock((unsigned char *)rootHash_hex, rootHash_bin, 32);
    // Adición de cada uno del hash al archivo JSON
    json_object_set_new(bloqueRoot, "hash", json_string(rootHash_hex));
    // Guardar la estructuración en un archivo JSON
    json_dump_file(bloqueGeneral, "dataBase.json", JSON_INDENT(4));
    // Liberar la memoria del arreglo y de los objetos
    json_decref(bloqueGeneral);
    json_decref(bloqueRoot);
    // Establecer los permisos posteriores solo de lectura
    chmod("dataBase.json", 0444);
    limpiar_pantalla();
    printf("\tAhora puede ocupar el programa con normalidad.\n\n");
}

void verificar_usuario()
{
    if (access("dataBase.json", F_OK) != -1) 
    {
        printf("\tHola de nuevo!\n\n");
        continuar();
        limpiar_pantalla();
    } 
    else
    {
        printf("\t\tAviso: Esta es la primera vez que ejecuta el programa.");
        printf(" Por favor, ingrese los datos requeridos para continuar.\n\n");
        crear_usuario();
        continuar();
        limpiar_pantalla();
    }
}

datos_crudos obtener_datos_crudos(json_t *infoUser)
{
    datos_crudos userX;
    userX.Salt = json_object_get(infoUser, "salt");
    userX.UserName = json_object_get(infoUser, "usuario");
    userX.Hash = json_object_get(infoUser, "hash");
    return userX;
}

datos obtener_datos(datos_crudos usuario)
{
    datos userX;
    userX.Salt_hex = json_string_value(usuario.Salt);
    userX.UserName = json_string_value(usuario.UserName);
    userX.Hash_hex = json_string_value(usuario.Hash);
    return userX;
}

int comprobar_password(const char *SaltInfo_hex, const char *HashInfo_hex)
{
    // Contraseña a comparar
    char test_password[256];
    printf("Contraseña: ");
    fflush(stdout);
    scanf("%255s%*c", test_password);
    // Conversión de la salt a binario
    unsigned char saltInfo_bin[8];
    EVP_DecodeBlock(saltInfo_bin, (const unsigned char *)SaltInfo_hex, strlen(SaltInfo_hex));
    // Aplicación del algoritmo de hash a la contraseña proporcionada
    unsigned char testHash_bin[32];
    calcular_hash(test_password, saltInfo_bin, testHash_bin);
    // Conversión del hash a hexadecimal
    char testHash_hex[8 * 2 + 1];
    EVP_EncodeBlock((unsigned char *)testHash_hex, testHash_bin, 32);
    // Si la comparación del hash generado con el hash almacenado coincide
    if (strcmp(testHash_hex, HashInfo_hex) == 0)
    {
        printf("\tContraseña correcta.\n");
        continuar();
        limpiar_pantalla();
        // Regresar el resultado de la comparación de la contraseña
        return 1;
    }
    else
    {
        printf("\tContraseña incorrecta.\n");
        continuar();
        limpiar_pantalla();
        // Regresar el resultado de la comparación de la contraseña
        return 0;
    }
}

int iniciar_sesion()
{
    // Archivo JSON
    json_t *repositorio;
    json_error_t error;
    // Lectura del archivo
    repositorio = json_load_file("dataBase.json", 0, &error);
    // Objeto del administrador almacenado en el archivo
    json_t *info_bloqueRoot = json_object_get(repositorio, "administrador");
    // Datos a procesar del administrador
    datos_crudos administrador = obtener_datos_crudos(info_bloqueRoot);
    // Datos procesados del administrador
    datos administradorUtil = obtener_datos(administrador);
    // Nombre de usuario a probar
    char testUserName[256];
    // Resultado de la comparación de la contraseña
    int check;
    // Tipo de usuario
    int privilegios;
    do
    {
        // Petición del usuario a probar
        printf("Usuario: ");
        fflush(stdout);
        scanf("%255s%*c", testUserName);
        // Si el usuario a probar es igual a los datos procesados del administrador
        if (strcmp(testUserName, administradorUtil.UserName) == 0)
        {
            // Verifica que la contraseña coincida
            check = comprobar_password(administradorUtil.Salt_hex, administradorUtil.Hash_hex);
            // Su tipo de usuario es administrador
            privilegios = 1;
        }
        // Sino, entonces no hay datos procesados asociados al usuario ingresado
        else
        {
            printf("\t\tAviso: El usuario no existe en su JSON. Por favor, intente de nuevo\n");
            continuar();
            limpiar_pantalla();
        }
    }while(check != 1); // Se repite el proceso hasta que la verificación coincida
    // Limpiar la memoria
    json_decref(repositorio);
    json_decref(info_bloqueRoot);
    // Regresar el tipo de usuario asociado a su inicio de sesión
    return privilegios;
}
