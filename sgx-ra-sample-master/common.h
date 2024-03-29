/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef __COMMON_H
#define __COMMON_H

/* Help keep our console messages clean and organzied */

#include <stdio.h>
#include <sgx_eid.h>
#include <sgx_error.h>

#ifdef _WIN32
# define MANAGEMENT_ENCLAVE "Enclave.signed.dll"
#else
# define MANAGEMENT_ENCLAVE "Enclave.signed.so"
# define OUTPUT_ENCLAVE "libenclave2.so"

#endif


#if defined(__cplusplus)
extern "C" {
#endif

void edividerWithText(const char *text);
void edivider();

void dividerWithText(FILE *fd, const char *text);
void divider(FILE *fd);

int eprintf(const char *format, ...);
int eputs(const char *s);


//Added for prototype
extern sgx_enclave_id_t e1_enclave_id;
extern sgx_enclave_id_t e2_enclave_id;

extern sgx_status_t statusEnclaveCall, statusEncryption, ret;
extern sgx_status_t global_ret; 
extern sgx_status_t global_sgxrv;

#if defined(__cplusplus)
}
#endif

#endif
