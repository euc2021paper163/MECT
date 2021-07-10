#define ENCLAVE_FILE "Enclave.signed.dll"
//#define ENCLAVE_FILE "Enclave.signed.dll"







#include "prototype.h"

int save_testdata_in_enclave(sgx_enclave_id_t* eid)
{
	sgx_status_t ret = SGX_SUCCESS;
	char testData[2][5][MAX_BUF_LEN] = {
		{ "ID1", "Max Mustermann", "Mann", "Trump", "RL" } ,   /*  initializers for row indexed by 0 */
		{ "ID2", "Eva Eversbusch", "Frau", "Clinton", "RW" }   /*  initializers for row indexed by 2 */
	};
    printf("\nAdding two sets of sample data to enclave internal data.\n");

    //Add testdata to enclave data
    for (int i = 0; i < 2; i++) {
        ret = takeSampleSets(*eid, testData[i][0], testData[i][1], testData[i][2], testData[i][3], testData[i][4]);
        if (ret != SGX_SUCCESS) {
            printf("\nApp: error %#x, failed to add sample data.\n", ret);
            return 1;
        }
        else {
            printf("\nAdded one sample line successfully.\n");
        }
    }
    return 0;
}

int save_data_in_enclave(sgx_enclave_id_t* eid, char data[5][MAX_BUF_LEN])
{
	sgx_status_t ret = SGX_SUCCESS;
//	char testData[2][5][MAX_BUF_LEN] = {
//		{ "ID1", "Max", "Frau", "Trump", "RL" } ,   /*  initializers for row indexed by 0 */
//		{ "ID2", "Eva", "Frau", "Clinton", "RW" }   /*  initializers for row indexed by 2 */
//	};

    printf("\nAdding a set of sample data to enclave internal data.\n");
    ret = takeSampleSets(*eid, data[0], data[1], data[2], data[3], data[4]);
    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to add sample data.\n", ret);
        return 1;
    }
    else {
        printf("\nAdded one sample line successfully.\n");
        return 0;
    }
    return 1;
}


