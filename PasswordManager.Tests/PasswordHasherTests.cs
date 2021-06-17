using PasswordManager.Common;
using Xunit;
using Xunit.Abstractions;

namespace PasswordManager.Tests
{
    public class PasswordHasherTests
    {
        private readonly ITestOutputHelper _outputHelper;

        public PasswordHasherTests(ITestOutputHelper outputHelper)
        {
            _outputHelper = outputHelper;
        }

        [Fact]
        public void GenerateHash()
        {
            using var passwordHasher = new PasswordHasher();
            var result = passwordHasher.HashPassword("Pa$$w0rd", 256);
            Assert.Equal(256, result.Hash.Length);
            Assert.Equal(32, result.Salt.Length);
        }

        [Fact]
        public void TestDifferentSalt()
        {
            using var passwordHasher = new PasswordHasher();
            var result1 = passwordHasher.HashPassword("Pa$$w0rd", 256);
            var result2 = passwordHasher.HashPassword("Pa$$w0rd", 256);
            Assert.NotEqual(result1.Hash, result2.Hash);
            Assert.NotEqual(result1.Salt, result2.Salt);

            Assert.Equal(32, result1.Salt.Length);
            Assert.Equal(32, result2.Salt.Length);
        }

        [Fact]
        public void TestMatching()
        {
            using var passwordHasher = new PasswordHasher();
            var result1 = passwordHasher.HashPassword("Pa$$w0rd", 256);
            var result2 = passwordHasher.HashPassword("Pa$$w0rd", result1.Salt, 256);

            Assert.Equal(result1.Hash, result2.Hash);
            Assert.Equal(result1.Salt, result2.Salt);

            Assert.Equal(32, result1.Salt.Length);
            Assert.Equal(32, result2.Salt.Length);
        }
    }
}