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

#ifndef __PROTOTYPE_H
#define __PROTOTYPE_H

#define MAX_BUF_LEN 20


//TODO check if all are necessry
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <iostream>
#include <string>
#include <stdio.h>

#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>

//AttestationStuff
#include "sgx_uae_service.h"
#include "quote_size.h" //stolen from GIT sgx ra example
#include "hexutil.h"
#include "base64.h"



int save_testdata_in_enclave(sgx_enclave_id_t* eid);
int save_data_in_enclave(sgx_enclave_id_t* eid, char data[5][MAX_BUF_LEN]);

#endif