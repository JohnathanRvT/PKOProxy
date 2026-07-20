#include <iostream>
#include <iomanip>
typedef unsigned char byte;
bool inline rol_byte_off(byte* pb, unsigned int offset, byte bits) {
byte val = pb[offset]; val = (val << bits) | (val >> (8 - bits)); pb[offset] = val; return true; }
bool inline ror_byte_off(byte* pb, unsigned int offset, byte bits) {
byte val = pb[offset]; val = (val >> bits) | (val << (8 - bits)); pb[offset] = val; return true; }
bool inline xor_byte_off(byte* pb, unsigned int offset, byte mask) {
pb[offset] ^= mask; return true; }
bool encrypt_B(char* src, unsigned int src_len, char* key, unsigned int key_len, bool en = true) {
unsigned int loop = src_len / key_len; unsigned int rcnt = src_len % key_len; char* p = NULL; unsigned int i, j;
if (en) { p = src; for (j = 0; j < loop; ++ j) for (i = 0; i < key_len; ++ i) { xor_byte_off((byte *)p, j * key_len + i, key[i]); rol_byte_off((byte *)p, j * key_len + i, key[i] % key_len + 1); } for (i = 0; i < rcnt; ++ i) { xor_byte_off((byte *)p, loop * key_len + i, key[i]); rol_byte_off((byte *)p, loop * key_len + i, key[i] % key_len + 1); } }
else { p = src; for (j = 0; j < loop; ++ j) for (i = 0; i < key_len; ++ i) { ror_byte_off((byte *)p, j * key_len + i, key[i] % key_len + 1); xor_byte_off((byte *)p, j * key_len + i, key[i]); } for (i = 0; i < rcnt; ++ i) { ror_byte_off((byte *)p, loop * key_len + i, key[i] % key_len + 1); xor_byte_off((byte *)p, loop * key_len + i, key[i]); } } return true; }
int main() {
char data[8] = {(char)0x11, (char)0x22, (char)0x33, (char)0x44, (char)0x55, (char)0x66, (char)0x77, (char)0x88};
char key[6] = {(char)0x99, (char)0x3a, (char)0x3c, (char)0x7b, (char)0x27, (char)0xb1};
encrypt_B(data, 8, key, 6, false);
std::cout << "C++ B decrypted: ";
for (int i = 0; i < 8; i++) {
std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)data[i] << " ";
}
std::cout << std::endl;
return 0; }
