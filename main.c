/*
    El programa utiliza Jansson y OpenSSL:
    Jansson 2.14: https://jansson.readthedocs.io/en/latest/gettingstarted.html#compiling-and-installing-jansson
    OpenSSL 3.0.7: https://www.openssl.org/source/

    Para poder compilar el programa, es necesario compilar e instalar las librerías mencionadas.
    Cuando esten instaladas, el programa se compila con: cc -o <namefile> <namefile>.c -ljansson -lssl -lcrypto
*/
#include "login.c"

int main(void)
{
    VerificacionUsuarios();
    //if(LogUser() == 1)
    //{
        // Función agregar
        // Función modificar
        // Función eliminar
        // Función consultar productos
        // Función regresar
    //}
    //else
    //{
        // Función consultar catálogo
        // Función realizar compra
        // Función regresar
    //}
    LogUser();
    return 0;
}
