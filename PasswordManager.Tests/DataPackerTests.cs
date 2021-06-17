using PasswordManager.Common;
using System;
using System.Security.Cryptography;
using Xunit;

namespace PasswordManager.Tests
{
    public class DataPackerTests : IDisposable
    {
        // Cryptographically secure random number generation
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;

        public DataPackerTests()
        {
            _cryptoServiceProvider = new RNGCryptoServiceProvider();
        }

        [Fact]
        public void TestPack()
        {
            var cipherText = new byte[512];

            var salt = new byte[Constants.SaltSize];
            var nonce = new byte[Constants.NounceSize];
            var tag = new byte[Constants.TagSize];

            _cryptoServiceProvider.GetBytes(cipherText);
            _cryptoServiceProvider.GetBytes(salt);
            _cryptoServiceProvider.GetBytes(nonce);
            _cryptoServiceProvider.GetBytes(tag);

            var result = DataPacker.PackData(salt, new DataEncryptor.EncryptedData
            {
                Data = cipherText,
                Nounce = nonce,
                Tag = tag
            });

            Assert.Equal(512 + Constants.FixedPackedSize, result.Length);
        }

        [Fact]
        public void TestPackAndUnpack()
        {
            var cipherText = new byte[512];

            var salt = new byte[Constants.SaltSize];
            var nonce = new byte[Constants.NounceSize];
            var tag = new byte[Constants.TagSize];

            _cryptoServiceProvider.GetBytes(cipherText);
            _cryptoServiceProvider.GetBytes(salt);
            _cryptoServiceProvider.GetBytes(nonce);
            _cryptoServiceProvider.GetBytes(tag);

            var result = DataPacker.PackData(salt, new DataEncryptor.EncryptedData
            {
                Data = cipherText,
                Nounce = nonce,
                Tag = tag
            });

            Assert.Equal(512 + Constants.FixedPackedSize, result.Length);

            var (unpackedSalt, unpackedData) = DataPacker.UnpackData(result);

            Assert.Equal(Constants.SaltSize, unpackedSalt.Length);
            Assert.Equal(512, unpackedData.Data.Length);
            Assert.Equal(Constants.NounceSize, unpackedData.Nounce.Length);
            Assert.Equal(Constants.TagSize, unpackedData.Tag.Length);

            Assert.Equal(salt, unpackedSalt);
            Assert.Equal(cipherText, unpackedData.Data);
            Assert.Equal(nonce, unpackedData.Nounce);
            Assert.Equal(tag, unpackedData.Tag);
        }

        public void Dispose()
        {
            _cryptoServiceProvider.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}