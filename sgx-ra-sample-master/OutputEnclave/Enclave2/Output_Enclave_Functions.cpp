#include "Output_Enclave_Functions.h"

extern int testDataCounter = 0;
extern struct raw_voting_data* testVotingDataRows = new raw_voting_data[10];

int general_output_function(int* integer_pointer, char* string_pointer, char function_identifier){
    int result_int = 0;
    char* result_char = "Output";
    switch(function_identifier){
        case 'O':{
            //Default case
            int trumpVotes = 0;
            break;}
        case 'T':{
            //Count_Trump_Votes
            int trumpVotes = 0;
            for (int i = 0; i < testDataCounter; i++) {
                if (*testVotingDataRows[i].choice == 'T') {
                    trumpVotes++;
                }
            }
            result_int = trumpVotes;
            break;}
        default:{
            //Default case
            break;}
    }
    //TODO check if pointer works correctly
    result_char = result_char;
    *integer_pointer = result_int;
    return 0;
}
