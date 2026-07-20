#include <iostream>
#include <iomanip>
#include <cstring>
#include "temp_des.h"
using namespace PKO;
int main() {
char key[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
char password[24] = "chap12345chap678901234";
char out[8] = {0};
CDES::RunDes(CDES::DECRYPT, CDES::ECB, key, out, 8, password, 24);
std::cout << "C++ decrypted: ";
for (int i = 0; i < 8; i++) {
std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)out[i] << " ";
}
std::cout << std::endl;
return 0; }
encrypt_B(data, 8, key, 6, false);
