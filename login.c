#include "login.h"

void ClearScreen()
{
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}
void Continue()
{
    #ifdef _WIN32
        system("pause");
    #else
        printf("Presione una tecla para continuar...\n");
        getchar();
    #endif
}

void CalculateHash(unsigned char *Password, unsigned char *Salt_bin, unsigned char *Hash_bin)
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

void CreacionUsuarios()
{
    // El objeto principal del archivo JSON
    json_t *bloqueGeneral = json_object();

    // El objeto de administrador del archivo JSON
    json_t *bloqueRoot = json_object();
    // Se agrega al objeto principal
    json_object_set_new(bloqueGeneral, "administrador", bloqueRoot);

    // El arreglo de usuarios del archivo JSON
    json_t *bloqueClientes = json_array();
    // Se agrega al objeto principal
    json_object_set_new(bloqueGeneral, "clientes", bloqueClientes);

    // Escalabilidad del proyecto

        // Un solo cliente como objeto del bloque de clientes en el archivo JSON
        json_t *clientePrincipal = json_object();
        // Se agrega al arreglo
        json_array_append_new(bloqueClientes, clientePrincipal);

        // (Opcional) un segundo cliente como objeto del bloque de clientes en el archivo JSON
        json_t *clienteOpcional = json_object();
        // Se agrega al arreglo
        json_array_append_new(bloqueClientes, clienteOpcional);

    // Generación de las semillas para cada uno de los usuarios

        // Semilla para el administrador
        unsigned char saltRoot_bin[8];
        RAND_bytes(saltRoot_bin, 8);

        // Semilla para el cliente principal
        unsigned char saltClientePrincipal_bin[8];
        RAND_bytes(saltClientePrincipal_bin, 8);

        // Semilla para el cliente opcional
        unsigned char saltClienteOpcional_bin[8];
        RAND_bytes(saltClienteOpcional_bin, 8);

    // Conversión de cada una de las semillas a hexadecimal

        // Semilla hexadecimal del administrador
        char saltRoot_hex[8 * 2 + 1];
        EVP_EncodeBlock((unsigned char *)saltRoot_hex, saltRoot_bin, 8);

        // Semilla hexadecimal del cliente principal
        char saltClientePrincipal_hex[8 * 2 + 1];
        EVP_EncodeBlock((unsigned char *)saltClientePrincipal_hex, saltClientePrincipal_bin, 8);

        // Semilla hexadecimal del cliente opcional
        char saltClienteOpcional_hex[8 * 2 + 1];
        EVP_EncodeBlock((unsigned char *)saltClienteOpcional_hex, saltClienteOpcional_bin, 8);

    // Adición de cada una de las semillas en hexadecimal al archivo JSON

        json_object_set_new(bloqueRoot, "salt", json_string(saltRoot_hex));
        json_object_set_new(clientePrincipal, "salt", json_string(saltClientePrincipal_hex));
        json_object_set_new(clienteOpcional, "salt", json_string(saltClienteOpcional_hex));

    // Creación de los usuarios

        // Usuario administrador

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
            ClearScreen();
            Continue();

        // Cliente principal

            ClearScreen();
            // Usuario con privilegios normales
            char mainUser[256];
            printf("Cliente principal: ");
            fflush(stdout);
            scanf("%255s%*c", mainUser);

            // (Inseguro) contraseña directa del cliente principal
            char mainUser_password[256];
            printf("Contraseña: ");
            fflush(stdout);
            scanf("%255s%*c", mainUser_password);
            ClearScreen();
            Continue();

        // Cliente opcional

            ClearScreen();
            // Usuario opcional con privilegios normales
            char optionalUser[256];
            printf("Cliente secundario: ");
            fflush(stdout);
            scanf("%255s%*c", optionalUser);

            // (Inseguro) contraseña directa del cliente opcional
            char optionalUser_password[256];
            printf("Contraseña: ");
            fflush(stdout);
            scanf("%255s%*c", optionalUser_password);
            ClearScreen();
            Continue();

    // Adición de cada uno de los usuarios al archivo JSON

        json_object_set_new(bloqueRoot, "usuario", json_string(root));
        json_object_set_new(clientePrincipal, "usuario", json_string(mainUser));
        json_object_set_new(clienteOpcional, "usuario", json_string(optionalUser));

    // Hasheo de las contraseñas de cada uno de los usuarios usando el algoritmo SHA256

        // Usuario administrador

            // Hash resultante del administrador
            unsigned char rootHash_bin[32];
            CalculateHash(root_password, saltRoot_bin, rootHash_bin);

        // Cliente principal

            // Hash resultante del administrador
            unsigned char mainUserHash_bin[32];
            CalculateHash(mainUser_password, saltClientePrincipal_bin, mainUserHash_bin);

        // Cliente opcional

            // Hash resultante del administrador
            unsigned char optionalUserHash_bin[32];
            CalculateHash(optionalUser_password, saltClienteOpcional_bin, optionalUserHash_bin);
    
    // Conversión de cada uno de los hashes a hexadecimal

        // Hash hexadecimal del administrador
        char rootHash_hex[32 * 2 + 1];
        EVP_EncodeBlock((unsigned char *)rootHash_hex, rootHash_bin, 32);

        // Hash hexadecimal del cliente principal
        char mainUserHash_hex[32 * 2 + 1];
        EVP_EncodeBlock((unsigned char *)mainUserHash_hex, mainUserHash_bin, 32);

        // Hash hexadecimal del cliente opcional
        char optionalUserHash_hex[32 * 2 + 1];
        EVP_EncodeBlock((unsigned char *)optionalUserHash_hex, optionalUserHash_bin, 32);

    // Adición de cada uno de los hashes en hexadecimal al archivo JSON

        json_object_set_new(bloqueRoot, "hash", json_string(rootHash_hex));
        json_object_set_new(clientePrincipal, "hash", json_string(mainUserHash_hex));
        json_object_set_new(clienteOpcional, "hash", json_string(optionalUserHash_hex));
    
    // Guardar la estructuración en un archivo JSON
    json_dump_file(bloqueGeneral, "dataBase.json", JSON_INDENT(4));

    // Liberar la memoria del arreglo y de los objetos
    json_decref(bloqueGeneral);
    json_decref(bloqueRoot);
    json_decref(bloqueClientes);
    json_decref(clientePrincipal);
    json_decref(clienteOpcional);

    // Establecer los permisos posteriores solo de lectura
    chmod("dataBase.json", 0444);

    ClearScreen();
    printf("\tAhora puede ocupar el programa con normalidad.\n\n");
}

void VerificacionUsuarios()
{
    if (access("dataBase.json", F_OK) != -1) 
    {
        printf("\tHola de nuevo!\n\n");
        Continue();
        ClearScreen();
    } 
    else
    {
        printf("\t\tAviso: Esta es la primera vez que ejecuta el programa.");
        printf(" Por favor, ingrese los datos requeridos para continuar.\n\n");
        CreacionUsuarios();
        Continue();
        ClearScreen();
    }
}

datosInutiles bloqueInutil(json_t *infoUser)
{
    datosInutiles userX;
    userX.Salt = json_object_get(infoUser, "salt");
    userX.UserName = json_object_get(infoUser, "usuario");
    userX.Hash = json_object_get(infoUser, "hash");
    return userX;
}

datosUtiles bloqueUtil(datosInutiles usuario)
{
    datosUtiles userX;
    userX.Salt_hex = json_string_value(usuario.Salt);
    userX.UserName = json_string_value(usuario.UserName);
    userX.Hash_hex = json_string_value(usuario.Hash);
    return userX;
}

int PasswordCheck(const char *SaltInfo_hex, const char *HashInfo_hex)
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
    CalculateHash(test_password, saltInfo_bin, testHash_bin);

    // Conversión del hash a hexadecimal
    char testHash_hex[8 * 2 + 1];
    EVP_EncodeBlock((unsigned char *)testHash_hex, testHash_bin, 32);

    // Si la comparación del hash generado con el hash almacenado coincide
    if (strcmp(testHash_hex, HashInfo_hex) == 0)
    {
        printf("\tContraseña correcta.\n");
        Continue();
        ClearScreen();
        // Regresar el resultado de la comparación de la contraseña
        return 1;
    }
    else
    {
        printf("\tContraseña incorrecta.\n");
        Continue();
        ClearScreen();
        // Regresar el resultado de la comparación de la contraseña
        return 0;
    }
}

int LogUser()
{
    // Archivo JSON
    json_t *repositorio;
    json_error_t error;

    // Lectura del archivo
    repositorio = json_load_file("dataBase.json", 0, &error);

    // Objeto del administrador almacenado en el archivo
    json_t *info_bloqueRoot = json_object_get(repositorio, "administrador");

	// Array del los clientes almacenado en el archivo
	json_t *info_bloqueClientes = json_object_get(repositorio, "clientes");

	// Objeto del cliente principal almacenado en el archivo
	json_t *info_clientePrincipal = json_array_get(info_bloqueClientes, 0);

	// Objeto del cliente opcional almacenado en el archivo
	json_t *info_clienteOpcional = json_array_get(info_bloqueClientes, 1);

    // Datos a procesar del administrador
    datosInutiles administrador = bloqueInutil(info_bloqueRoot);

	// Datos a procesar del cliente principal
    datosInutiles clientePrincipal = bloqueInutil(info_clientePrincipal);

	// Datos a procesar del cliente opcional
    datosInutiles clienteOpcional = bloqueInutil(info_clienteOpcional);

    // Datos procesados del administrador
    datosUtiles administradorUtil = bloqueUtil(administrador);

	// Datos procesados del cliente principal
    datosUtiles clientePrincipalUtil = bloqueUtil(clientePrincipal);

	// Datos procesados del cliente opcional
    datosUtiles clienteOpcionalUtil = bloqueUtil(clienteOpcional);
	
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
            check = PasswordCheck(administradorUtil.Salt_hex, administradorUtil.Hash_hex);

            // Su tipo de usuario es administrador
            privilegios = 1;
        }

        // O si el usuario a probar es igual a los datos procesados del cliente principal
        else if (strcmp(testUserName, clientePrincipalUtil.UserName) == 0)
        {
            // Verifica que la contraseña coincida
            check = PasswordCheck(clientePrincipalUtil.Salt_hex, clientePrincipalUtil.Hash_hex);

            // Su tipo de usuario es normal
            privilegios = 0;
        }

        // O si el usuario a probar es igual a los datos procesados del cliente principal
        else if (strcmp(testUserName, clienteOpcionalUtil.UserName) == 0)
        {
            // Verifica que la contraseña coincida
            check = PasswordCheck(clienteOpcionalUtil.Salt_hex, clienteOpcionalUtil.Hash_hex);

            // Su tipo de usuario es normal
            privilegios = 0;
        }

        // Sino, entonces no hay datos procesados asociados al usuario ingresado
        else
        {
            printf("\t\tAviso: El usuario no existe en su JSON. Por favor, intente de nuevo\n");
            Continue();
            ClearScreen();
        }

    }while(check != 1); // Se repite el proceso hasta que la verificación coincida

    // Limpiar la memoria
    json_decref(repositorio);
    json_decref(info_bloqueRoot);
    json_decref(info_bloqueClientes);
    json_decref(info_clientePrincipal);
    json_decref(info_clienteOpcional);

    // Regresar el tipo de usuario asociado a su inicio de sesión
    return privilegios;
}
