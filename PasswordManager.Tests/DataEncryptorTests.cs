using PasswordManager.Common;
using System;
using System.Security.Cryptography;
using Xunit;

namespace PasswordManager.Tests
{
    public class DataEncryptorTests : IDisposable
    {
        // Cryptographically secure random number generation
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;

        public DataEncryptorTests()
        {
            _cryptoServiceProvider = new RNGCryptoServiceProvider();
        }

        [Fact]
        public void TestEncrypt()
        {
            // Generate a random 256 bit key
            var key = new byte[256 / 8];
            _cryptoServiceProvider.GetBytes(key);

            var data = new byte[] { 0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x08, 0x03, 0x08, 0x03 };

            using var encryptor = new DataEncryptor();
            var encryptedData = encryptor.Encrypt(key, data);

            Assert.Equal(data.Length, encryptedData.Data.Length);
            Assert.Equal(AesGcm.TagByteSizes.MaxSize, encryptedData.Tag.Length);
            Assert.Equal(AesGcm.NonceByteSizes.MaxSize, encryptedData.Nounce.Length);

            Assert.NotEqual(data, encryptedData.Data);
        }

        [Fact]
        public void TestEncryptAndDecrypt()
        {
            // Generate a random 256 bit key
            var key = new byte[256 / 8];
            _cryptoServiceProvider.GetBytes(key);

            var key2 = new byte[256 / 8];
            _cryptoServiceProvider.GetBytes(key2);

            var data = new byte[] { 0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x08, 0x03, 0x08, 0x03 };

            using var encryptor = new DataEncryptor();
            var encryptedData = encryptor.Encrypt(key, data);

            // Decrypt with incorrect key
            Assert.Throws<CryptographicException>(() =>
                encryptor.Decrypt(key2,
                    new DataEncryptor.EncryptedData
                    { Data = encryptedData.Data, Nounce = encryptedData.Nounce, Tag = encryptedData.Tag }));

            // Decrypt with correct key
            var decryptedData = encryptor.Decrypt(key,
                new DataEncryptor.EncryptedData
                { Data = encryptedData.Data, Nounce = encryptedData.Nounce, Tag = encryptedData.Tag });

            // Ensure data is the same
            Assert.Equal(data, decryptedData);
        }

        public void Dispose()
        {
            _cryptoServiceProvider.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}