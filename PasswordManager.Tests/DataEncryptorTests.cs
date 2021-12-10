using PasswordManager.Common;
using System.Security.Cryptography;
using Xunit;

namespace PasswordManager.Tests;

public class DataEncryptorTests
{
    [Fact]
    public void TestEncrypt()
    {
        // Generate a random 256 bit key
        var key = new byte[256 / 8];
        RandomNumberGenerator.Fill(key);

        var data = new byte[] { 0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x08, 0x03, 0x08, 0x03 };

        var encryptedData = DataEncryptor.Encrypt(key, data);

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
        RandomNumberGenerator.Fill(key);

        var key2 = new byte[256 / 8];
        RandomNumberGenerator.Fill(key2);

        var data = new byte[] { 0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x08, 0x03, 0x08, 0x03 };

        var encryptedData = DataEncryptor.Encrypt(key, data);

        // Decrypt with incorrect key
        Assert.Throws<CryptographicException>(() =>
            DataEncryptor.Decrypt(key2,
                new DataEncryptor.EncryptedData
                    { Data = encryptedData.Data, Nounce = encryptedData.Nounce, Tag = encryptedData.Tag }));

        // Decrypt with correct key
        var decryptedData = DataEncryptor.Decrypt(key,
            new DataEncryptor.EncryptedData
                { Data = encryptedData.Data, Nounce = encryptedData.Nounce, Tag = encryptedData.Tag });

        // Ensure data is the same
        Assert.Equal(data, decryptedData);
    }
}