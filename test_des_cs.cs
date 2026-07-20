using System;
using System.Text;
using PkoProxyClient;
namespace TestDes {
class Program {
static void Main() {
byte[] key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
byte[] pwd = new byte[23];
byte[] pwdChars = Encoding.ASCII.GetBytes("chap12345chap678901234");
Array.Copy(pwdChars, pwd, 22);
byte[] outBytes = new byte[8];
PkoDes.RunDes(PkoDes.DECRYPT, PkoDes.ECB, key, outBytes, pwd);
Console.Write("C# decrypted: ");
foreach (byte b in outBytes) {
Console.Write($"{b:x2} ");
}
Console.WriteLine(); } } }
