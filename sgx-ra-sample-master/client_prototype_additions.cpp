#include "client_prototype_additions.h"

void emit_debug(const char *buf){
    printf("\nDEBUG OUT OF ENCLAVE: %s\n", buf);
}

void sendMyMessage(MsgIO *msgio,char* myType, int sz){
	int rv;
	msgio->send(myType, sz);
	fprintf(stderr, "Sent message: %s\n", myType);
	fprintf(fplog, "Sent message: %s\n", myType);

	char * incomingStuff;
	sleep(1);
	rv= msgio->read((void **) &incomingStuff, NULL);
	if ( rv == 0 ) {
		fprintf(stderr, "protocol error reading msg\n");
	} else if ( rv == -1 ) {
		fprintf(stderr, "system error occurred while reading msg\n");
	}
	fprintf(stderr, "   Received message: %s\n", incomingStuff);
	fprintf(fplog, "   Received message: %s\n", incomingStuff);
}

char* encryptMyMessage(char* message, size_t *encMessageLenExport){
	printf("Encrypting original message: %s\n", message);
	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message));
	char *encMessage = (char *)malloc((encMessageLen + 1) * sizeof(char));
	size_t messageLen = strlen(message);
	global_ret = encryptMessage(e1_enclave_id, message, messageLen, encMessage, encMessageLen);
	if (global_ret != SGX_SUCCESS) {
		//enclave_ra_close(eid, &global_sgxrv, ra_ctx);
		fprintf(stderr, "Error: Encrypt password with mk: %08x\n", global_ret);
		fprintf(fplog, "Error: Encrypt password with mk: %08x\n", global_ret);
		//delete msgio;
	}
	encMessage[encMessageLen] = '\0';
//		printf("Encrypted message: %s\n", encMessage);
	printf("Encrypted hex msg: ");
	for (int i = 0; i< encMessageLen+1;i++) 		printf("0x%02x ",encMessage[i] );;
	printf("\n\n");
	printf("\nEncrypted hex msg2nd Time: \n");
	print_hexstring(stderr, &encMessage, encMessageLen+1);
	
	*encMessageLenExport = encMessageLen;
	return encMessage ;
}





/////////////////////////////////////////////////////////////
// Testing functions of the Enclaves:
/////////////////////////////////////////////////////////////

//Wrapper function for calling policy engine
int generate_enclave_from_policy_request_wrapper(char* requested_rights){
	//Building Enclave
	return generate_policy(requested_rights);
}

void list_available_enclaves(){
	//Loading OutputEnclave
    printf("\nAvailable Enclaves:\n");
    printf("\nManagementEnclave - EnclaveID %llx",e1_enclave_id);
    printf("\nOutputEnclave     - EnclaveID %llx",e2_enclave_id);
}    

void test_crate_session_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest){
    uint32_t secondary_enclave_status;
	//Test Create session between Enclave1(Source) and Enclave2(Destination)
	sgx_status_t primary_enclave_status = test_create_session(enclave_id_from, &secondary_enclave_status,
		enclave_id_from, enclave_id_dest);
	if (primary_enclave_status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_create_session Ecall failed: Error code is %x", 
			primary_enclave_status);
	}
	else
	{
		if(secondary_enclave_status==0)
		{
			printf("\n\nSecure Channel Establishment between Source (E1) and \
				Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\nSession establishment and key exchange failure between \
				Source (E1) and Destination (E2): Error code is %x", secondary_enclave_status);
		}
	}
}

void test_message_exchange_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest){
	uint32_t secondary_enclave_status;
	//Test message exchange between Enclave1(Source) and Enclave2(Destination)
	sgx_status_t primary_enclave_status = test_message_exchange(enclave_id_from, &secondary_enclave_status, 
		enclave_id_from, enclave_id_dest);
	if (primary_enclave_status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", 
			primary_enclave_status);
	}
	else
	{
		if(secondary_enclave_status==0)
		{
			printf("\n\nMessage Exchange between Source (E1) and Destination \
				(E2) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nMessage Exchange failure between Source (E1) and \
				Destination (E2): Error code is %x", secondary_enclave_status);
		}
	}
}

void test_enclave_to_enclave_call_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest){
	uint32_t secondary_enclave_status;
	//Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
	sgx_status_t primary_enclave_status = test_enclave_to_enclave_call(enclave_id_from, &secondary_enclave_status, enclave_id_from, enclave_id_dest);
	if (primary_enclave_status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", primary_enclave_status);
	}
	else
	{
		if(secondary_enclave_status==0)
		{
			printf("\n\nEnclave to Enclave Call between Source (E1) and Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nEnclave to Enclave Call failure between Source (E1) and Destination (E2): Error code is %x", secondary_enclave_status);
		}
	}
}

void test_copy_all_data_enclave_to_enclave_call_wrapper(sgx_enclave_id_t enclave_id_from, sgx_enclave_id_t enclave_id_dest){
	uint32_t secondary_enclave_status;
	//Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
	sgx_status_t primary_enclave_status = copy_data_enclave_to_enclave_call(enclave_id_from, &secondary_enclave_status, enclave_id_from, enclave_id_dest);
	if (secondary_enclave_status != SGX_SUCCESS)
	{
		printf("Enclave1_copy_data_enclave_to_enclave_call Ecall failed: Error code is %x", primary_enclave_status);
	}
	else
	{
		if(secondary_enclave_status==0)
		{
			printf("\n\nEnclave to Enclave Copy Call between Source (E1) and Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nEnclave to Enclave Copy Call failure between Source (E1) and Destination (E2): Error code is %x", secondary_enclave_status);
		}
	}
}

void Enclave2_general_output_function_wrapper(sgx_enclave_id_t enclave_id_to_perform_output, char function_identifier){
	uint32_t secondary_enclave_status;
	printf("\nStarting Outputfunction\n");
	//Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
	int myOutputInt;
	char myOutputString;
	sgx_status_t primary_enclave_status = Enclave2_general_output_function(enclave_id_to_perform_output,(int*) &secondary_enclave_status, &myOutputInt, &myOutputString, function_identifier);
	if (primary_enclave_status!=SGX_SUCCESS)
	{
		printf("Enclave1_copy_data_enclave_to_enclave_call Ecall failed: Error code is %x\n", primary_enclave_status);
	}
	else
	{
		if(secondary_enclave_status==0)
		{
			if (myOutputInt)    printf("Received Int:    %i \n", myOutputInt);
			if (0) printf("Received String: %s \n\n", myOutputString);
		}
		else
		{
			printf("\n\nEnclave to Enclave Copy Call failure between Source (E1) and Destination (E2): Error code is %x\n", secondary_enclave_status);
		}
	}
}

void get_number_of_votes_wrapper(sgx_enclave_id_t enclave_to_start_eid)
{
	int primary_enclave_status = 0;
	int local_result = 0;
	primary_enclave_status = getNumberOfTrumpVotes(enclave_to_start_eid, &local_result);
	if (primary_enclave_status != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to count Trump votes.\n", primary_enclave_status);
	}
	printf("\nYou have the following number of Trump votes: %i\n", local_result);
}

void add_enclave_to_map_wrapper(sgx_enclave_id_t enclave_eid_to_add){
    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(enclave_eid_to_add,
		enclave_temp_no));
}


