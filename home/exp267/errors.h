#ifndef ERRORS_H
#define ERRORS_H

// TODO - Allocate negative values to these codes
// TODO - Typedef an error code as int and update throughout

#define SUCCESS 0

#define ERROR_DCID_GEN -11

#define ERROR_NEW_STREAM -21
#define ERROR_HOST_LOOKUP -22
#define ERROR_COULD_NOT_OPEN_CONNECTION_FD -23
#define ERROR_GET_SOCKNAME -24

#define ERROR_WOLFSSL_SETUP -31

#define ERROR_OUT_OF_MEMORY -41

#define ERROR_NO_NEW_MESSAGE -51

#define ERROR_DRAINING_STATE -61
#define ERROR_DROP_CONNECTION -62

#define ERROR_SOCKET -71

#endif