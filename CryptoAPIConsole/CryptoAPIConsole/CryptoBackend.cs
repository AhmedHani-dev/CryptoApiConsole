using System.Security.Cryptography;
using System.Text;

namespace CryptoAPIConsole;
public class CryptoBackend
{
    private static byte[] fixedSalt = Convert.FromBase64String("rgbah+AZtko0FlU0W6BCaaAuvKKlF2dAFHjrEVZTF+8RKQPOyn/RO9D8LOCLlAOxgoPad0HcQS5IAWYIq5RsMmihILUdWHe3Gr7YZJUNGtzPqZZI+VtmTS4Hvb+LHbahD5dhWey1moFlYmrxpjkisI1OPkS/1EnWaiaUf/9iVEw=");
    private static int iterationCount = 37649;
    static private RNGCryptoServiceProvider rnd = new RNGCryptoServiceProvider();

    public static byte[] deriveKey(String password)
    {
        Rfc2898DeriveBytes deriver = new Rfc2898DeriveBytes(password, fixedSalt)
        {
            IterationCount = iterationCount
        };

        return deriver.GetBytes(32);
    }

    private static byte[] getRandomBytes(int count)
    {
        byte[] res = new byte[count];
        rnd.GetBytes(res);
        return res;
    }

    private static Aes getCipher()
    {
        return new AesManaged()
        {
            Mode = CipherMode.CBC,
            Padding = PaddingMode.PKCS7
        };
    }

    public static String encrypt(byte[] keyBytes, String plaintext)
    {
        using (Aes crypto = getCipher())
        {
            crypto.Key = keyBytes;
            crypto.IV = getRandomBytes(crypto.BlockSize / 8);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            MemoryStream ms = new MemoryStream();
            ms.Write(crypto.IV, 0, crypto.IV.Length);
            using (CryptoStream cs = new CryptoStream(ms, crypto.CreateEncryptor(crypto.Key, crypto.IV), CryptoStreamMode.Write))
                cs.Write(plainBytes, 0, plainBytes.Length);
            ms.Close();
            var cipherBytes = ms.ToArray();

            HMACSHA256 mac = new HMACSHA256();
            mac.Key = keyBytes;

            var macBytes = mac.ComputeHash(cipherBytes);

            MemoryStream resStream = new MemoryStream();
            resStream.Write(cipherBytes, 0, cipherBytes.Length);
            resStream.Write(macBytes, 0, macBytes.Length);
            return Convert.ToBase64String(resStream.ToArray());

        }
    }

    public static String decrypt(byte[] keyBytes, String ciphertext)
    {
        using (Aes crypto = getCipher())
        {
            HMAC mac = new HMACSHA256();
            mac.Key = keyBytes;

            byte[] allBytes = Convert.FromBase64String(ciphertext);

            byte[] iv = new byte[crypto.BlockSize / 8];
            byte[] macBytes = new byte[mac.HashSize / 8];
            byte[] cipherBytes = new byte[allBytes.Length - iv.Length - macBytes.Length];

            using (MemoryStream ms = new MemoryStream(allBytes, /*writable*/false))
            {
                ms.Read(iv, 0, iv.Length);
                ms.Read(cipherBytes, 0, cipherBytes.Length);
                ms.Read(macBytes, 0, macBytes.Length);
            }

            crypto.Key = keyBytes;
            crypto.IV = iv;

            byte[] maccable = new byte[iv.Length + cipherBytes.Length];
            iv.CopyTo(maccable, 0);
            cipherBytes.CopyTo(maccable, iv.Length);

            byte[] mBytes = mac.ComputeHash(new MemoryStream(maccable, /*writable*/false));

            if (!equalBytes(mBytes, macBytes))
                throw new Exception("Decryption Failed");

            MemoryStream output = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(output, crypto.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(cipherBytes, 0, cipherBytes.Length);
            }
            output.Close();
            return Encoding.UTF8.GetString(output.ToArray());
        }
    }

    public static bool equalBytes(byte[] b1, byte[] b2)
    {
        int minLen = (b1.Length > b2.Length) ? b2.Length : b1.Length;
        bool res = b1.Length == b2.Length;
        for (int i = 0; i < minLen; i++)
        {
            res = res && (b1[i] == b2[i]);
        }
        return res;
    }
}
