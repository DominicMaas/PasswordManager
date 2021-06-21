using PasswordManager.Common;
using PasswordManager.Types;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace PasswordManager.Tests
{
    public class IntegrationTests : IDisposable
    {
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;

        public IntegrationTests()
        {
            _cryptoServiceProvider = new RNGCryptoServiceProvider();
        }

        [Fact]
        public void TestGenerateAndHash()
        {
            using var passwordGenerator = new PasswordGenerator();
            using var passwordHasher = new PasswordHasher();

            var randomPassword = passwordGenerator.GeneratePassword(80);
            var hashedPassword = passwordHasher.HashPassword(randomPassword, 256);
            Assert.Equal(256, hashedPassword.Hash.Length);
            Assert.Equal(32, hashedPassword.Salt.Length);
        }

        [Fact]
        public void TestGenerateAndHashAndEncrypt()
        {
            using var passwordGenerator = new PasswordGenerator();
            using var passwordHasher = new PasswordHasher();
            using var dataEncryptor = new DataEncryptor();

            var data = new byte[1_000_000];
            _cryptoServiceProvider.GetBytes(data);

            var randomPassword = passwordGenerator.GeneratePassword(80);
            var key = passwordHasher.HashPassword(randomPassword, 256 / 8);
            var encryptedData = dataEncryptor.Encrypt(key.Hash, data);

            Assert.NotEqual(data, encryptedData.Data);
        }

        [Fact]
        public void TestGenerateAndHashAndEncryptAndDecrypt()
        {
            using var passwordGenerator = new PasswordGenerator();
            using var passwordHasher = new PasswordHasher();
            using var dataEncryptor = new DataEncryptor();

            var data = new byte[1_000_000];
            _cryptoServiceProvider.GetBytes(data);

            var randomPassword = passwordGenerator.GeneratePassword(80);
            var key = passwordHasher.HashPassword(randomPassword, 256 / 8);
            var encryptedData = dataEncryptor.Encrypt(key.Hash, data);

            // ------ Stored to file ------ //
            var cipherText = encryptedData.Data;
            var salt = key.Salt;
            var nounce = encryptedData.Nounce;
            var tag = encryptedData.Tag;
            // ------ Stored to file ------ //

            var newKey = passwordHasher.HashPassword(randomPassword, salt, 256 / 8); // User re-enters password, use stored salt

            Assert.Equal(key.Hash, newKey.Hash);
            Assert.Equal(key.Salt, newKey.Salt);

            var plainText = dataEncryptor.Decrypt(newKey.Hash,
                new DataEncryptor.EncryptedData { Data = cipherText, Nounce = nounce, Tag = tag });

            Assert.Equal(data, plainText);
        }

        [Fact]
        public void TestGenerateAndHashAndEncryptAndPackAndUnpackAndDecrypt()
        {
            using var passwordGenerator = new PasswordGenerator();
            using var passwordHasher = new PasswordHasher();
            using var dataEncryptor = new DataEncryptor();

            var data = new byte[1_000_000];
            _cryptoServiceProvider.GetBytes(data);

            var randomPassword = passwordGenerator.GeneratePassword(80);
            var key = passwordHasher.HashPassword(randomPassword, 256 / 8);
            var encryptedData = dataEncryptor.Encrypt(key.Hash, data);

            // ------ Stored to file ------ //
            var packedData = DataPacker.PackData(key.Salt, encryptedData);

            var (salt, unpackedData) = DataPacker.UnpackData(packedData);
            var cipherText = unpackedData.Data;
            var nounce = unpackedData.Nounce;
            var tag = unpackedData.Tag;
            // ------ Stored to file ------ //

            var newKey = passwordHasher.HashPassword(randomPassword, salt, 256 / 8); // User re-enters password, use stored salt

            Assert.Equal(key.Hash, newKey.Hash);
            Assert.Equal(key.Salt, newKey.Salt);

            var plainText = dataEncryptor.Decrypt(newKey.Hash,
                new DataEncryptor.EncryptedData { Data = cipherText, Nounce = nounce, Tag = tag });

            Assert.Equal(data, plainText);
        }

        [Fact]
        public void TestVaultTypeSerializeAndDeserialize()
        {
            var vault = new VaultType { Passwords = new Dictionary<string, string>() };
            vault.Passwords.Add("demo-password", "Pa%%w0rd");

            var bytes = vault.Serialize();
            var vaultFromJson = VaultType.Deserialize(bytes);

            Assert.Equal(vault.Passwords["demo-password"], vaultFromJson!.Passwords["demo-password"]);
        }

        [Fact]
        public void TestGenerateAndHashAndSerializeAndEncryptAndPackAndUnpackAndDecryptAndDeserialize()
        {
            using var passwordGenerator = new PasswordGenerator();
            using var passwordHasher = new PasswordHasher();
            using var dataEncryptor = new DataEncryptor();

            var vault = new VaultType { Passwords = new Dictionary<string, string>() };
            vault.Passwords.Add("website_1", passwordGenerator.GeneratePassword(80));
            vault.Passwords.Add("website_2", passwordGenerator.GeneratePassword(80));
            vault.Passwords.Add("website_3", passwordGenerator.GeneratePassword(80));
            vault.Passwords.Add("website_4", passwordGenerator.GeneratePassword(80));

            var randomPassword = passwordGenerator.GeneratePassword(80);
            var key = passwordHasher.HashPassword(randomPassword, 256 / 8);
            var encryptedData = dataEncryptor.Encrypt(key.Hash, vault.Serialize());

            // ------ Stored to file ------ //
            var packedData = DataPacker.PackData(key.Salt, encryptedData);

            var (salt, unpackedData) = DataPacker.UnpackData(packedData);
            var cipherText = unpackedData.Data;
            var nounce = unpackedData.Nounce;
            var tag = unpackedData.Tag;
            // ------ Stored to file ------ //

            var newKey = passwordHasher.HashPassword(randomPassword, salt, 256 / 8); // User re-enters password, use stored salt

            Assert.Equal(key.Hash, newKey.Hash);
            Assert.Equal(key.Salt, newKey.Salt);

            var plainText = dataEncryptor.Decrypt(newKey.Hash,
                new DataEncryptor.EncryptedData { Data = cipherText, Nounce = nounce, Tag = tag });

            var storedVault = VaultType.Deserialize(plainText);
            Assert.NotNull(storedVault);

            foreach (var (id, pass) in vault.Passwords)
            {
                Assert.Equal(pass, storedVault.Passwords[id]);
            }
        }

        public void Dispose()
        {
            _cryptoServiceProvider.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}