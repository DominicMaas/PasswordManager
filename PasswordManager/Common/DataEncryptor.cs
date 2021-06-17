using System;
using System.Security.Cryptography;

namespace PasswordManager.Common
{
    public class DataEncryptor : IDisposable
    {
        // Cryptographically secure random number generation
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;

        /// <summary>
        ///     Create a new instance of 'DataEncryptor'
        /// </summary>
        public DataEncryptor(RNGCryptoServiceProvider? cryptoServiceProvider = null)
        {
            _cryptoServiceProvider = cryptoServiceProvider ?? new RNGCryptoServiceProvider();
        }

        public EncryptedData Encrypt(byte[] key, byte[] data)
        {
            // Use AES in GCM mode as per
            // https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes
            using var aes = new AesGcm(key);

            // Generate the nounce (maximum possible size)
            var nounce = new byte[Constants.NounceSize];
            _cryptoServiceProvider.GetBytes(nounce);

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

        public byte[] Decrypt(byte[] key, EncryptedData data)
        {
            // Use AES in GCM mode as per
            // https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes
            using var aes = new AesGcm(key);

            var plainText = new byte[data.Data.Length];
            aes.Decrypt(data.Nounce, data.Data, data.Tag, plainText);

            return plainText;
        }

        public void Dispose()
        {
            _cryptoServiceProvider.Dispose();
            GC.SuppressFinalize(this);
        }

        public struct EncryptedData
        {
            public byte[] Data;
            public byte[] Nounce;
            public byte[] Tag;
        }
    }
}