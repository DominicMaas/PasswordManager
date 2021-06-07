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
    }
}