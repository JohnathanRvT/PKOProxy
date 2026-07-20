#include <iostream>
#include <string>
int main() {
std::string chap_string = "[07-20 12:48:45:517]";
std::cout << "len: " << chap_string.length() << std::endl;
for(int i=0; i<chap_string.length(); i++) std::cout << i << ":" << chap_string[i] << " ";
std::cout << std::endl;
return 0; }
