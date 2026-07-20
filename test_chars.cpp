#include <iostream>
#include <string>
int main() {
std::string chap_string = "[07-20 12:48:45:517]";
int last4 = int(*(int*)(chap_string.c_str() + chap_string.length() - 4));
std::cout << "last4: " << last4 << std::endl;
return 0; }
