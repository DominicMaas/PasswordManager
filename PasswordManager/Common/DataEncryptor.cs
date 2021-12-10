using System.Security.Cryptography;

namespace PasswordManager.Common;

public static class DataEncryptor
{
    public static EncryptedData Encrypt(byte[] key, byte[] data)
    {
        // Use AES in GCM mode as per
        // https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes
        using var aes = new AesGcm(key);

        // Generate the nounce (maximum possible size)
        var nounce = new byte[Constants.NounceSize];
        RandomNumberGenerator.Fill(nounce);

        var encryptedData = new byte[data.Length];
        var tag = new byte[Constants.TagSize]; // use large tag sizes!
        aes.Encrypt(nounce, data, encryptedData, tag);

        return new EncryptedData
        {
            Data = encryptedData,
            Nounce = nounce,
            Tag = tag
        };
    }

    public static byte[] Decrypt(byte[] key, EncryptedData data)
    {
        // Use AES in GCM mode as per
        // https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes
        using var aes = new AesGcm(key);

        var plainText = new byte[data.Data.Length];
        aes.Decrypt(data.Nounce, data.Data, data.Tag, plainText);

        return plainText;
    }
    
    public struct EncryptedData
    {
        public byte[] Data;
        public byte[] Nounce;
        public byte[] Tag;
    }
}