#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>

#define MAXFEATURES_NUMBER 20

using namespace std;

int generate_policy(char* rights);
void check_rights(bool* right_is_aproved, char right_has_char, char* rights);

#endif
