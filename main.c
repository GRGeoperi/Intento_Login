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
    verificar_usuario();
    iniciar_sesion();
    return 0;
}
