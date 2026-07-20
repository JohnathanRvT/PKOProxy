using System;
using System.Text;

namespace PkoProxyClient
{
    public enum EncryptType
    {
        CS = 0,
        SC = 1
    }

    public enum DecryptType
    {
        CS = 0,
        SC = 1
    }

    public static class PkoDes
    {
        public const bool ENCRYPT = false;
        public const bool DECRYPT = true;
        public const bool ECB = false;
        public const bool CBC = true;

        // initial permutation IP
        private static readonly sbyte[] IP_Table = new sbyte[64] {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        };
        // final permutation IP^-1
        private static readonly sbyte[] IPR_Table = new sbyte[64] {
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
        };
        // expansion operation matrix
        private static readonly sbyte[] E_Table = new sbyte[48] {
            32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
            8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
        };
        // 32-bit permutation function P used on the output of the S-boxes
        private static readonly sbyte[] P_Table = new sbyte[32] {
            16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
            2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
        };
        // permuted choice table (key)
        private static readonly sbyte[] PC1_Table = new sbyte[56] {
            57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
        };
        // permuted choice key (table)
        private static readonly sbyte[] PC2_Table = new sbyte[48] {
            14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        };
        // number left rotations of pc1
        private static readonly sbyte[] LOOP_Table = new sbyte[16] {
            1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
        };
        // The S-boxes
        private static readonly byte[,,] S_Box = new byte[8, 4, 16] {
            {
                // S1
                { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
                {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
                {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
                { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
            },
            {
                // S2
                { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
                {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
                {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
                { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
            },
            {
                // S3
                { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
                { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
                { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
                {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
            },
            {
                // S4
                {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
                { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
                { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
                {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
            },
            {
                // S5
                {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
                { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
                {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
                { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
            },
            {
                // S6
                { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
                { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
                {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
                {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
            },
            {
                // S7
                {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
                { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
                {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
                {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
            },
            {
                // S8
                { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
                {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
                {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
                {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
            }
        };

        private static void ByteToBit(bool[] Out, byte[] In, int bits)
        {
            for (int i = 0; i < bits; ++i)
                Out[i] = ((In[i >> 3] >> ((7 - i) & 7)) & 1) != 0;
        }

        private static void BitToByte(byte[] Out, bool[] In, int bits)
        {
            Array.Clear(Out, 0, bits >> 3);
            for (int i = 0; i < bits; ++i)
            {
                if (In[i])
                {
                    Out[i >> 3] |= (byte)(1 << ((7 - i) & 7));
                }
            }
        }

        private static void RotateL(bool[] In, int len, int loop)
        {
            bool[] tmp = new bool[256];
            Array.Copy(In, tmp, loop);
            Array.Copy(In, loop, In, 0, len - loop);
            Array.Copy(tmp, 0, In, len - loop, loop);
        }

        private static void Xor(bool[] InA, bool[] InB, int len)
        {
            for (int i = 0; i < len; ++i)
                InA[i] ^= InB[i];
        }

        private static void Transform(bool[] Out, bool[] In, sbyte[] Table, int len)
        {
            bool[] tmp = new bool[256];
            for (int i = 0; i < len; ++i)
                tmp[i] = In[Table[i] - 1];
            Array.Copy(tmp, Out, len);
        }

        private static void S_func(bool[] Out, int outOff, bool[] In, int inOff)
        {
            for (int i = 0; i < 8; ++i)
            {
                int currIn = inOff + i * 6;
                int currOut = outOff + i * 4;
                int j = ((In[currIn + 0] ? 1 : 0) << 1) + (In[currIn + 5] ? 1 : 0);
                int k = ((In[currIn + 1] ? 1 : 0) << 3) + ((In[currIn + 2] ? 1 : 0) << 2) + ((In[currIn + 3] ? 1 : 0) << 1) + (In[currIn + 4] ? 1 : 0);

                for (int l = 0; l < 4; ++l)
                {
                    Out[currOut + l] = ((S_Box[i, j, k] >> (3 - l)) & 1) != 0;
                }
            }
        }

        private static void F_func(bool[] In, bool[] Ki)
        {
            bool[] MR = new bool[48];
            Transform(MR, In, E_Table, 48);
            Xor(MR, Ki, 48);
            S_func(In, 0, MR, 0);
            Transform(In, In, P_Table, 32);
        }

        private static void SetSubKey(bool[,][] pSubKey, int keyIdx, byte[] Key, int keyOff)
        {
            bool[] K = new bool[64];
            byte[] blockKey = new byte[8];
            Array.Copy(Key, keyOff, blockKey, 0, 8);
            ByteToBit(K, blockKey, 64);
            Transform(K, K, PC1_Table, 56);

            bool[] KL = new bool[28];
            bool[] KR = new bool[28];
            Array.Copy(K, 0, KL, 0, 28);
            Array.Copy(K, 28, KR, 0, 28);

            for (int i = 0; i < 16; ++i)
            {
                RotateL(KL, 28, LOOP_Table[i]);
                RotateL(KR, 28, LOOP_Table[i]);
                Array.Copy(KL, 0, K, 0, 28);
                Array.Copy(KR, 0, K, 28, 28);
                Transform(pSubKey[keyIdx, i], K, PC2_Table, 48);
            }
        }

        private static void DES(byte[] Out, int outOff, byte[] In, int inOff, bool[,][] pSubKey, int keyIdx, bool Type)
        {
            bool[] M = new bool[64];
            byte[] blockIn = new byte[8];
            Array.Copy(In, inOff, blockIn, 0, 8);
            ByteToBit(M, blockIn, 64);
            Transform(M, M, IP_Table, 64);

            bool[] Li = new bool[32];
            bool[] Ri = new bool[32];
            Array.Copy(M, 0, Li, 0, 32);
            Array.Copy(M, 32, Ri, 0, 32);

            bool[] tmp = new bool[32];
            if (Type == ENCRYPT)
            {
                for (int i = 0; i < 16; ++i)
                {
                    Array.Copy(Ri, tmp, 32);
                    F_func(Ri, pSubKey[keyIdx, i]);
                    Xor(Ri, Li, 32);
                    Array.Copy(tmp, Li, 32);
                }
            }
            else
            {
                for (int i = 15; i >= 0; --i)
                {
                    Array.Copy(Ri, tmp, 32);
                    F_func(Ri, pSubKey[keyIdx, i]);
                    Xor(Ri, Li, 32);
                    Array.Copy(tmp, Li, 32);
                }
            }

            Array.Copy(Li, 0, M, 0, 32);
            Array.Copy(Ri, 0, M, 32, 32);
            RotateL(M, 64, 32);
            Transform(M, M, IPR_Table, 64);

            byte[] blockOut = new byte[8];
            BitToByte(blockOut, M, 64);
            Array.Copy(blockOut, 0, Out, outOff, 8);
        }

        public static byte[] RunPad(byte[] In)
        {
            int datalen = In.Length;
            int res = datalen & 7;
            int padlen = datalen + 8 - res;
            byte[] Out = new byte[padlen];
            Array.Copy(In, Out, datalen);
            return Out;
        }

        public static bool RunDes(bool bType, bool bMode, byte[] In, byte[] Out, byte[] Key)
        {
            int datalen = In.Length;
            int keylen = Key.Length;

            if (datalen == 0 || (datalen & 7) != 0 || keylen < 8)
                return false;

            // Allocate m_SubKey: [3 keys, 16 rounds, 48 subkey bits]
            bool[,][] m_SubKey = new bool[3, 16][];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    m_SubKey[i, j] = new bool[48];
                }
            }

            int nKey = (keylen >> 3) > 3 ? 3 : (keylen >> 3);
            for (int i = 0; i < nKey; i++)
            {
                SetSubKey(m_SubKey, i, Key, i << 3);
            }

            if (bMode == ECB)
            {
                int blocks = datalen >> 3;
                if (nKey == 1)
                {
                    for (int i = 0; i < blocks; ++i)
                    {
                        DES(Out, i * 8, In, i * 8, m_SubKey, 0, bType);
                    }
                }
                else if (nKey == 2)
                {
                    for (int i = 0; i < blocks; ++i)
                    {
                        DES(Out, i * 8, In, i * 8, m_SubKey, 0, bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, 1, !bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, 0, bType);
                    }
                }
                else
                {
                    for (int i = 0; i < blocks; ++i)
                    {
                        DES(Out, i * 8, In, i * 8, m_SubKey, bType ? 2 : 0, bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, 1, !bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, bType ? 0 : 2, bType);
                    }
                }
            }
            else
            {
                // CBC Mode (if ever needed, translated for completeness)
                byte[] cvec = new byte[8];
                byte[] cvin = new byte[8];
                int blocks = datalen >> 3;

                if (nKey == 1)
                {
                    for (int i = 0; i < blocks; ++i)
                    {
                        if (bType == ENCRYPT)
                        {
                            for (int j = 0; j < 8; ++j)
                                cvin[j] = (byte)(In[i * 8 + j] ^ cvec[j]);
                        }
                        else
                        {
                            Array.Copy(In, i * 8, cvin, 0, 8);
                        }

                        DES(Out, i * 8, cvin, 0, m_SubKey, 0, bType);

                        if (bType == ENCRYPT)
                        {
                            Array.Copy(Out, i * 8, cvec, 0, 8);
                        }
                        else
                        {
                            for (int j = 0; j < 8; ++j)
                                Out[i * 8 + j] ^= cvec[j];
                            Array.Copy(cvin, cvec, 8);
                        }
                    }
                }
                else if (nKey == 2)
                {
                    for (int i = 0; i < blocks; ++i)
                    {
                        if (bType == ENCRYPT)
                        {
                            for (int j = 0; j < 8; ++j)
                                cvin[j] = (byte)(In[i * 8 + j] ^ cvec[j]);
                        }
                        else
                        {
                            Array.Copy(In, i * 8, cvin, 0, 8);
                        }

                        DES(Out, i * 8, cvin, 0, m_SubKey, 0, bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, 1, !bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, 0, bType);

                        if (bType == ENCRYPT)
                        {
                            Array.Copy(Out, i * 8, cvec, 0, 8);
                        }
                        else
                        {
                            for (int j = 0; j < 8; ++j)
                                Out[i * 8 + j] ^= cvec[j];
                            Array.Copy(cvin, cvec, 8);
                        }
                    }
                }
                else
                {
                    for (int i = 0; i < blocks; ++i)
                    {
                        if (bType == ENCRYPT)
                        {
                            for (int j = 0; j < 8; ++j)
                                cvin[j] = (byte)(In[i * 8 + j] ^ cvec[j]);
                        }
                        else
                        {
                            Array.Copy(In, i * 8, cvin, 0, 8);
                        }

                        DES(Out, i * 8, cvin, 0, m_SubKey, bType ? 2 : 0, bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, 1, !bType);
                        DES(Out, i * 8, Out, i * 8, m_SubKey, bType ? 0 : 2, bType);

                        if (bType == ENCRYPT)
                        {
                            Array.Copy(Out, i * 8, cvec, 0, 8);
                        }
                        else
                        {
                            for (int j = 0; j < 8; ++j)
                                Out[i * 8 + j] ^= cvec[j];
                            Array.Copy(cvin, cvec, 8);
                        }
                    }
                }
            }

            return true;
        }
    }

    public static class PacketEncoder
    {
        public static bool encrypt_B(byte[] src, byte[] key, bool en = true)
        {
            int src_len = src.Length;
            int key_len = key.Length;
            if (key_len == 0 || src_len == 0) return false;

            int loop = src_len / key_len;
            int rcnt = src_len % key_len;

            if (en)
            {
                for (int j = 0; j < loop; ++j)
                {
                    for (int i = 0; i < key_len; ++i)
                    {
                        int idx = j * key_len + i;
                        byte k = key[i];
                        int shift = k % key_len + 1;
                        src[idx] ^= k;
                        src[idx] = (byte)((src[idx] << shift) | (src[idx] >> (8 - shift)));
                    }
                }
                for (int i = 0; i < rcnt; ++i)
                {
                    int idx = loop * key_len + i;
                    byte k = key[i];
                    int shift = k % key_len + 1;
                    src[idx] ^= k;
                    src[idx] = (byte)((src[idx] << shift) | (src[idx] >> (8 - shift)));
                }
            }
            else
            {
                for (int j = 0; j < loop; ++j)
                {
                    for (int i = 0; i < key_len; ++i)
                    {
                        int idx = j * key_len + i;
                        byte k = key[i];
                        int shift = k % key_len + 1;
                        src[idx] = (byte)((src[idx] >> shift) | (src[idx] << (8 - shift)));
                        src[idx] ^= k;
                    }
                }
                for (int i = 0; i < rcnt; ++i)
                {
                    int idx = loop * key_len + i;
                    byte k = key[i];
                    int shift = k % key_len + 1;
                    src[idx] = (byte)((src[idx] >> shift) | (src[idx] << (8 - shift)));
                    src[idx] ^= k;
                }
            }
            return true;
        }

        public static void init_Noise(int nNoise, byte[] szKey)
        {
            szKey[0] = (byte)(nNoise & 0x01);
            szKey[1] = (byte)(nNoise & 0x02);
            szKey[2] = (byte)(nNoise & 0x04);
            szKey[3] = (byte)(nNoise & 0x08);
        }

        public static bool encrypt_Noise(byte[] szKey, byte[] src)
        {
            int src_len = src.Length;
            int nLen = src_len >> 2;
            if (nLen > 8)
            {
                nLen = 8;
            }
            int nCount = 0;
            for (int i = 0; i < nLen; i++)
            {
                src[nCount++] ^= szKey[3];
                src[nCount++] ^= szKey[2];
                src[nCount++] ^= szKey[1];
                src[nCount++] ^= szKey[0];
            }

            if (src_len >= 8)
            {
                szKey[0] = (byte)(src[7] ^ (src[3] ^ 1));
                szKey[1] = (byte)(src[6] ^ (src[2] ^ 2));
                szKey[2] = (byte)(src[5] ^ (src[1] ^ 3));
                szKey[3] = (byte)(src[4] ^ (src[0] ^ 4));
            }

            return true;
        }

        public static bool decrypt_Noise(byte[] szKey, byte[] src)
        {
            int src_len = src.Length;
            byte[] szTemp = new byte[4];
            if (src_len >= 8)
            {
                szTemp[0] = (byte)(src[7] ^ (src[3] ^ 1));
                szTemp[1] = (byte)(src[6] ^ (src[2] ^ 2));
                szTemp[2] = (byte)(src[5] ^ (src[1] ^ 3));
                szTemp[3] = (byte)(src[4] ^ (src[0] ^ 4));
            }

            int nLen = src_len >> 2;
            if (nLen > 8)
            {
                nLen = 8;
            }
            int nCount = 0;
            for (int i = 0; i < nLen; i++)
            {
                src[nCount++] ^= szKey[3];
                src[nCount++] ^= szKey[2];
                src[nCount++] ^= szKey[1];
                src[nCount++] ^= szKey[0];
            }

            if (src_len >= 8)
            {
                szKey[0] = szTemp[0];
                szKey[1] = szTemp[1];
                szKey[2] = szTemp[2];
                szKey[3] = szTemp[3];
            }

            return true;
        }
    }

    public class PacketEncryptor
    {
        private bool m_enabled = false;
        private byte[] m_session_key = new byte[16];
        private ushort m_session_key_length = 0;
        private byte[][] m_keys = new byte[4][];

        public PacketEncryptor()
        {
            for (int i = 0; i < 4; i++)
            {
                m_keys[i] = new byte[4];
            }
        }

        public bool Enabled => m_enabled;

        public void Init(bool enabled, ushort version, string chap_string, byte[] password, byte[] key)
        {
            m_enabled = enabled;
            if (m_enabled)
            {
                // MSVC C++ short int is 16-bit signed integer
                short key_data = (short)(version * version * 0x1232222);

                // Grab last 4 bytes of chap_string
                byte[] chapBytes = Encoding.ASCII.GetBytes(chap_string);
                int last4 = 0;
                if (chapBytes.Length >= 4)
                {
                    last4 = BitConverter.ToInt32(chapBytes, chapBytes.Length - 4);
                }
                int noise = key_data * last4;

                // CDES::RunDes (DECRYPT, ECB)
                byte[] passwordKey = password;
                byte[] decryptedSessionKey = new byte[key.Length];
                PkoDes.RunDes(PkoDes.DECRYPT, PkoDes.ECB, key, decryptedSessionKey, passwordKey);

                Array.Copy(decryptedSessionKey, m_session_key, Math.Min(m_session_key.Length, decryptedSessionKey.Length));
                m_session_key_length = 6;

                PacketEncoder.init_Noise(noise, m_keys[0]);
                PacketEncoder.init_Noise(noise, m_keys[1]);
                PacketEncoder.init_Noise(noise, m_keys[2]);
                PacketEncoder.init_Noise(noise, m_keys[3]);
            }
            else
            {
                Array.Clear(m_session_key, 0, m_session_key.Length);
                m_session_key_length = 0;
            }
        }

        public void Encrypt(byte[] data, EncryptType type)
        {
            byte[] key = type == EncryptType.CS ? m_keys[2] : m_keys[3];
            PacketEncoder.encrypt_Noise(key, data);

            byte[] actualSessionKey = new byte[m_session_key_length];
            Array.Copy(m_session_key, actualSessionKey, m_session_key_length);
            PacketEncoder.encrypt_B(data, actualSessionKey, true);
        }

        public void Decrypt(byte[] data, DecryptType type)
        {
            byte[] key = type == DecryptType.CS ? m_keys[0] : m_keys[1];

            byte[] actualSessionKey = new byte[m_session_key_length];
            Array.Copy(m_session_key, actualSessionKey, m_session_key_length);
            PacketEncoder.encrypt_B(data, actualSessionKey, false);

            PacketEncoder.decrypt_Noise(key, data);
        }
    }

    public static class PasswordEncoder
    {
        public static byte[] Encode(string password, string chap_string)
        {
            byte[] srcBytes = Encoding.ASCII.GetBytes(chap_string);
            byte[] szPad = PkoDes.RunPad(srcBytes);

            byte[] passwordKey = Encoding.ASCII.GetBytes(password);
            byte[] encoded_password = new byte[szPad.Length];

            PkoDes.RunDes(PkoDes.ENCRYPT, PkoDes.ECB, szPad, encoded_password, passwordKey);
            return encoded_password;
        }
    }
}
