#include "policy_engine.h"
#include "string.h"
#include <chrono>
#include <ctime>
#include "fileio.h"


void check_rights(bool* right_is_aproved, char right_has_char, char* rights){
int rights_len = strlen(rights);
    for (int p=0; p< rights_len; p++){
        if (rights[p] == right_has_char){
            *right_is_aproved = true;
        }        
    }
    return;
}

int generate_policy(char* rights){

    // checking which rights/features should be hardcoded
    bool Count_Trump_Votes = false;
    check_rights(&Count_Trump_Votes, 'T', rights);
    bool Zero_Case = false;
    check_rights(&Zero_Case, 'O', rights);

    // Beginning to write the file containing the hardcoded policies
    ofstream myfile;
    myfile.open ("OutputEnclave/Enclave2/Output_Enclave_Functions.cpp");
    myfile << "#include \"Output_Enclave_Functions.h\"\n";
    myfile << "\n";
    myfile << "extern int testDataCounter = 0;\n";
    myfile << "extern struct raw_voting_data* testVotingDataRows = new raw_voting_data[10];\n";
    myfile << "\n";
    myfile << "int general_output_function(int* integer_pointer, char* string_pointer, char function_identifier){\n";
    myfile << "    int result_int = 0;\n";
    myfile << "    char* result_char = \"Output\";\n";
    myfile << "    switch(function_identifier){\n";

    //Feature/Function 1
    if(Zero_Case) {
    myfile << "        case 'O':{\n";
    myfile << "            //Default case\n";
    myfile << "            int trumpVotes = 0;\n";
    myfile << "            break;}\n";
    }

    //Feature/Function 2
    if(Count_Trump_Votes) {
    myfile << "        case 'T':{\n";
    myfile << "            //Count_Trump_Votes\n";
    myfile << "            int trumpVotes = 0;\n";
    myfile << "            for (int i = 0; i < testDataCounter; i++) {\n";
    myfile << "                if (*testVotingDataRows[i].choice == 'T') {\n";
    myfile << "                    trumpVotes++;\n";
    myfile << "                }\n";
    myfile << "            }\n";
    myfile << "            result_int = trumpVotes;\n";
    myfile << "            break;}\n";
    }

    //default case
    if(true) {
    myfile << "        default:{\n";
    myfile << "            //Default case\n";
    myfile << "            break;}\n";
    }

    myfile << "    }\n";
    myfile << "    //TODO check if pointer works correctly\n";
    myfile << "    result_char = result_char;\n";
    myfile << "    *integer_pointer = result_int;\n";
    myfile << "    return 0;\n";
    myfile << "}\n";
    myfile.close();

    printf("\nCalling System makefile function: \n");

	//saving to statistics.txt
	ofstream fout3;
	fout3.open("statistics_compileOutputEnclave.txt", std::ios::app);
    std::chrono::time_point<std::chrono::system_clock> start, end; 

    system("make cleanOutputEnclave --directory OutputEnclave/ > DebugOutput_Makefile_OutputEnclave1.txt");
 
    start = std::chrono::high_resolution_clock::now(); 
    system("make --directory OutputEnclave/ 2> DebugOutput_Makefile_OutputEnclave2.txt");
    end = std::chrono::high_resolution_clock::now(); 
 
    std::chrono::duration<double> elapsed_seconds = end - start; 
    std::time_t end_time = std::chrono::high_resolution_clock::to_time_t(end);   
    std::cout << "Compile OutputEnclave: elapsed time:" << elapsed_seconds.count() << " s.   \tFinished computation at:"  << std::ctime(&end_time); 
	fout3 << "Compile OutputEnclave: elapsed time:" << elapsed_seconds.count() << " s.   \tFinished computation at:"  << std::ctime(&end_time); 
	fout3.close();
    return 0;
};