using System;
using System.Text;

namespace PkoProxyClient
{
    public static class PkoTest
    {
        public static bool RunTests()
        {
            Console.WriteLine("Running PKO C# Cryptography Tests...");

            try
            {
                // Test 1: DES Pad and Single Key ECB Encrypt/Decrypt
                byte[] plaintext = Encoding.ASCII.GetBytes("HelloPKOWorld!");
                byte[] key = Encoding.ASCII.GetBytes("mypassword123"); // 13 bytes, nKey = 1

                byte[] padded = PkoDes.RunPad(plaintext);
                byte[] encrypted = new byte[padded.Length];
                byte[] decrypted = new byte[padded.Length];

                if (!PkoDes.RunDes(PkoDes.ENCRYPT, PkoDes.ECB, padded, encrypted, key))
                {
                    Console.WriteLine("FAIL: RunDes Encrypt failed");
                    return false;
                }

                if (!PkoDes.RunDes(PkoDes.DECRYPT, PkoDes.ECB, encrypted, decrypted, key))
                {
                    Console.WriteLine("FAIL: RunDes Decrypt failed");
                    return false;
                }

                string decStr = Encoding.ASCII.GetString(decrypted).TrimEnd('\0');
                if (decStr != "HelloPKOWorld!")
                {
                    Console.WriteLine($"FAIL: Decrypted string '{decStr}' does not match original 'HelloPKOWorld!'");
                    return false;
                }
                Console.WriteLine("PASS: CDES ECB 1-key Encryption and Decryption");

                // Test 2: TripleDES ECB 2-Keys and 3-Keys
                byte[] key2 = Encoding.ASCII.GetBytes("key12345key67890"); // 16 bytes, nKey = 2
                Array.Clear(encrypted, 0, encrypted.Length);
                Array.Clear(decrypted, 0, decrypted.Length);

                PkoDes.RunDes(PkoDes.ENCRYPT, PkoDes.ECB, padded, encrypted, key2);
                PkoDes.RunDes(PkoDes.DECRYPT, PkoDes.ECB, encrypted, decrypted, key2);
                decStr = Encoding.ASCII.GetString(decrypted).TrimEnd('\0');
                if (decStr != "HelloPKOWorld!")
                {
                    Console.WriteLine($"FAIL: 3DES 2-key decrypted string '{decStr}' incorrect");
                    return false;
                }
                Console.WriteLine("PASS: CDES ECB 2-key 3DES");

                byte[] key3 = Encoding.ASCII.GetBytes("key12345key67890keyabcde"); // 24 bytes, nKey = 3
                Array.Clear(encrypted, 0, encrypted.Length);
                Array.Clear(decrypted, 0, decrypted.Length);

                PkoDes.RunDes(PkoDes.ENCRYPT, PkoDes.ECB, padded, encrypted, key3);
                PkoDes.RunDes(PkoDes.DECRYPT, PkoDes.ECB, encrypted, decrypted, key3);
                decStr = Encoding.ASCII.GetString(decrypted).TrimEnd('\0');
                if (decStr != "HelloPKOWorld!")
                {
                    Console.WriteLine($"FAIL: 3DES 3-key decrypted string '{decStr}' incorrect");
                    return false;
                }
                Console.WriteLine("PASS: CDES ECB 3-key 3DES");

                // Test 3: PasswordEncoder Encode
                byte[] pwdEncoded = PasswordEncoder.Encode("my_super_password", "chap12345chap678");
                if (pwdEncoded == null || pwdEncoded.Length == 0)
                {
                    Console.WriteLine("FAIL: PasswordEncoder returned empty bytes");
                    return false;
                }
                Console.WriteLine($"PASS: PasswordEncoder.Encode. Output Length: {pwdEncoded.Length}");

                // Test 4: PacketEncoder encrypt_B and decrypt_B
                byte[] payload = Encoding.ASCII.GetBytes("A very secure message that we want to encrypt with 'B' algorithm!");
                byte[] sessionKey = new byte[] { 0x05, 0xF1, 0x32, 0x1A, 0xCC, 0x48 }; // 6 bytes
                byte[] payloadCopy = (byte[])payload.Clone();

                PacketEncoder.encrypt_B(payloadCopy, sessionKey, true);
                PacketEncoder.encrypt_B(payloadCopy, sessionKey, false);

                string bDecStr = Encoding.ASCII.GetString(payloadCopy);
                if (bDecStr != "A very secure message that we want to encrypt with 'B' algorithm!")
                {
                    Console.WriteLine($"FAIL: encrypt_B/decrypt_B is not symmetric. Got: '{bDecStr}'");
                    return false;
                }
                Console.WriteLine("PASS: PacketEncoder 'B' Algorithm symmetry");

                // Test 5: PacketEncoder encrypt_Noise and decrypt_Noise (using separate synced keys)
                byte[] encryptNoiseKey = new byte[] { 0x01, 0x02, 0x04, 0x08 };
                byte[] decryptNoiseKey = new byte[] { 0x01, 0x02, 0x04, 0x08 };
                byte[] noisePayload = Encoding.ASCII.GetBytes("PacketWith8+Bytes");
                byte[] noisePayloadCopy = (byte[])noisePayload.Clone();

                PacketEncoder.encrypt_Noise(encryptNoiseKey, noisePayloadCopy);
                PacketEncoder.decrypt_Noise(decryptNoiseKey, noisePayloadCopy);

                string noiseDecStr = Encoding.ASCII.GetString(noisePayloadCopy);
                if (noiseDecStr != "PacketWith8+Bytes")
                {
                    Console.WriteLine($"FAIL: Noise Algorithm is not symmetric. Got: '{noiseDecStr}'");
                    return false;
                }
                Console.WriteLine("PASS: PacketEncoder Noise Algorithm symmetry");

                // Test 6: Binary IO
                var writer = new PkoPacketWriter();
                writer.WriteUint16(42);
                writer.WriteUint32(0xDEADBEEF);
                writer.WriteString("PKORules!");
                byte[] serialized = writer.ToArray();

                var pktReader = new PkoPacketReader(serialized);
                ushort u16 = pktReader.ReadUint16();
                uint u32 = pktReader.ReadUint32();
                string s = pktReader.ReadString();

                if (u16 != 42 || u32 != 0xDEADBEEF || s != "PKORules!")
                {
                    Console.WriteLine($"FAIL: Binary IO mismatch. Got: {u16}, 0x{u32:X}, '{s}'");
                    return false;
                }
                Console.WriteLine("PASS: PkoPacketWriter and PkoPacketReader");

                Console.WriteLine("\nALL TESTS PASSED SUCCESSFULLY!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAIL: Exception thrown during tests: {ex.Message}\n{ex.StackTrace}");
                return false;
            }
        }
    }
}
