using PasswordManager.Common;
using Xunit;

namespace PasswordManager.Tests
{
    public class IntegrationTests
    {
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
            
            var data = new byte[] {0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x08, 0x03, 0x08, 0x03};
            
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
            
            var data = new byte[] {0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x08, 0x03, 0x08, 0x03};
            
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
                new DataEncryptor.EncryptedData {Data = cipherText, Nounce = nounce, Tag = tag});
            
            Assert.Equal(data, plainText);
        }
    }
}