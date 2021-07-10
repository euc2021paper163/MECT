#include "sgx_eid.h"
#include "error_codes.h"
#include "datatypes.h"
#include "sgx_urts.h"
#include "dh_session_protocol.h"
#include "sgx_dh.h"
#include <cstddef>

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <intrin.h>
#include <wincrypt.h>
#include "win32/getopt.h"
#else
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

//Added for Prototype
#include "prototype.h"
#include "Enclave2_u.h"
#include "dh_session_protocol.h"
#include "policy_engine.h"
#include "UntrustedEnclaveMessageExchange.h"

#ifndef CLIENT_PROTOTYPE_ADDITIONS
#define CLIENT_PROTOTYPE_ADDITIONS

#ifdef __cplusplus
extern "C" {
#endif
    
void sendMyMessage(MsgIO *msgio,char* myType, int sz);
void emit_debug(const char *buf);
char* encryptMyMessage(char* message, size_t *encMessageLenExport);

void test_crate_session_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest);
void test_message_exchange_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest);
void test_enclave_to_enclave_call_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest);
void test_copy_all_data_enclave_to_enclave_call_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest);

void Enclave2_general_output_function_wrapper(sgx_enclave_id_t enclave_id_to_perform_output, char function_identifier);

void get_number_of_votes_wrapper(sgx_enclave_id_t enclave_to_start_eid);
void add_enclave_to_map_wrapper(sgx_enclave_id_t enclave_eid_to_add);

void list_available_enclaves();

#ifdef __cplusplus
}
#endif

#endif