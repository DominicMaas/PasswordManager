using PasswordManager.Common;
using Xunit;

namespace PasswordManager.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void GenerateHash()
    {
        var result = PasswordHasher.HashPassword("Pa$$w0rd", 256);
        Assert.Equal(256, result.Hash.Length);
        Assert.Equal(32, result.Salt.Length);
    }

    [Fact]
    public void TestDifferentSalt()
    {
        var result1 = PasswordHasher.HashPassword("Pa$$w0rd", 256);
        var result2 = PasswordHasher.HashPassword("Pa$$w0rd", 256);
        Assert.NotEqual(result1.Hash, result2.Hash);
        Assert.NotEqual(result1.Salt, result2.Salt);

        Assert.Equal(32, result1.Salt.Length);
        Assert.Equal(32, result2.Salt.Length);
    }

    [Fact]
    public void TestMatching()
    {
        var result1 = PasswordHasher.HashPassword("Pa$$w0rd", 256);
        var result2 = PasswordHasher.HashPassword("Pa$$w0rd", result1.Salt, 256);

        Assert.Equal(result1.Hash, result2.Hash);
        Assert.Equal(result1.Salt, result2.Salt);

        Assert.Equal(32, result1.Salt.Length);
        Assert.Equal(32, result2.Salt.Length);
    }
}