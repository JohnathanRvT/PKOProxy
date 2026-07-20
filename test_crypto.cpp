#include <iostream>
#include <string>
int main() {
unsigned short int version = 136;
std::string chap_string = "[07-20 12:48:45:517]";
short int key_data = version * version * 0x1232222;
int noise = key_data * int(*(int*)(chap_string.c_str() + chap_string.length() - 4));
std::cout << "C++ key_data: " << (int)key_data << std::endl;
std::cout << "C++ noise: " << noise << std::endl;
return 0; }
