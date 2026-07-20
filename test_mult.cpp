#include <iostream>
int main() {
unsigned short int version = 136;
unsigned long long r1 = (unsigned long long)version * version * 0x1232222;
unsigned int r2 = version * version * 0x1232222;
short int r3 = version * version * 0x1232222;
std::cout << "r1: " << r1 << std::endl;
std::cout << "r2: " << r2 << std::endl;
std::cout << "r3: " << r3 << std::endl;
return 0; }
