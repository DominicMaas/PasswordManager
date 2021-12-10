using PasswordManager.Common;
using PasswordManager.Types;
using System.Security.Cryptography;
using Xunit;

namespace PasswordManager.Tests;

public class IntegrationTests
{
    [Fact]
    public void TestGenerateAndHash()
    {
        var randomPassword = PasswordGenerator.GeneratePassword(80);
        var hashedPassword = PasswordHasher.HashPassword(randomPassword, 256);
        
        Assert.Equal(256, hashedPassword.Hash.Length);
        Assert.Equal(32, hashedPassword.Salt.Length);
    }

    [Fact]
    public void TestGenerateAndHashAndEncrypt()
    {
        var data = new byte[1_000_000];
        RandomNumberGenerator.Fill(data);

        var randomPassword = PasswordGenerator.GeneratePassword(80);
        var key = PasswordHasher.HashPassword(randomPassword, 256 / 8);
        var encryptedData = DataEncryptor.Encrypt(key.Hash, data);

        Assert.NotEqual(data, encryptedData.Data);
    }

    [Fact]
    public void TestGenerateAndHashAndEncryptAndDecrypt()
    {
        var data = new byte[1_000_000];
        RandomNumberGenerator.Fill(data);

        var randomPassword = PasswordGenerator.GeneratePassword(80);
        var key = PasswordHasher.HashPassword(randomPassword, 256 / 8);
        var encryptedData = DataEncryptor.Encrypt(key.Hash, data);

        // ------ Stored to file ------ //
        var cipherText = encryptedData.Data;
        var salt = key.Salt;
        var nounce = encryptedData.Nounce;
        var tag = encryptedData.Tag;
        // ------ Stored to file ------ //

        var newKey = PasswordHasher.HashPassword(randomPassword, salt, 256 / 8); // User re-enters password, use stored salt

        Assert.Equal(key.Hash, newKey.Hash);
        Assert.Equal(key.Salt, newKey.Salt);

        var plainText = DataEncryptor.Decrypt(newKey.Hash,
            new DataEncryptor.EncryptedData { Data = cipherText, Nounce = nounce, Tag = tag });

        Assert.Equal(data, plainText);
    }

    [Fact]
    public void TestGenerateAndHashAndEncryptAndPackAndUnpackAndDecrypt()
    {
        var data = new byte[1_000_000];
        RandomNumberGenerator.Fill(data);

        var randomPassword = PasswordGenerator.GeneratePassword(80);
        var key = PasswordHasher.HashPassword(randomPassword, 256 / 8);
        var encryptedData = DataEncryptor.Encrypt(key.Hash, data);

        // ------ Stored to file ------ //
        var packedData = DataPacker.PackData(key.Salt, encryptedData);

        var (salt, unpackedData) = DataPacker.UnpackData(packedData);
        var cipherText = unpackedData.Data;
        var nounce = unpackedData.Nounce;
        var tag = unpackedData.Tag;
        // ------ Stored to file ------ //

        var newKey = PasswordHasher.HashPassword(randomPassword, salt, 256 / 8); // User re-enters password, use stored salt

        Assert.Equal(key.Hash, newKey.Hash);
        Assert.Equal(key.Salt, newKey.Salt);

        var plainText = DataEncryptor.Decrypt(newKey.Hash,
            new DataEncryptor.EncryptedData { Data = cipherText, Nounce = nounce, Tag = tag });

        Assert.Equal(data, plainText);
    }

    [Fact]
    public void TestVaultTypeSerializeAndDeserialize()
    {
        var vault = new VaultType { Passwords = new Dictionary<string, string> { { "demo-password", "Pa%%w0rd" } } };

        var bytes = vault.Serialize();
        var vaultFromJson = VaultType.Deserialize(bytes);

        Assert.Equal(vault.Passwords["demo-password"], vaultFromJson!.Passwords["demo-password"]);
    }

    [Fact]
    public void TestGenerateAndHashAndSerializeAndEncryptAndPackAndUnpackAndDecryptAndDeserialize()
    {
        var vault = new VaultType { Passwords = new Dictionary<string, string>
            {
                { "website_1", PasswordGenerator.GeneratePassword(80) },
                { "website_2", PasswordGenerator.GeneratePassword(80) },
                { "website_3", PasswordGenerator.GeneratePassword(80) },
                { "website_4", PasswordGenerator.GeneratePassword(80) }
            }
        };

        var randomPassword = PasswordGenerator.GeneratePassword(80);
        var key = PasswordHasher.HashPassword(randomPassword, 256 / 8);
        var encryptedData = DataEncryptor.Encrypt(key.Hash, vault.Serialize());

        // ------ Stored to file ------ //
        var packedData = DataPacker.PackData(key.Salt, encryptedData);

        var (salt, unpackedData) = DataPacker.UnpackData(packedData);
        var cipherText = unpackedData.Data;
        var nounce = unpackedData.Nounce;
        var tag = unpackedData.Tag;
        // ------ Stored to file ------ //

        var newKey = PasswordHasher.HashPassword(randomPassword, salt, 256 / 8); // User re-enters password, use stored salt

        Assert.Equal(key.Hash, newKey.Hash);
        Assert.Equal(key.Salt, newKey.Salt);

        var plainText = DataEncryptor.Decrypt(newKey.Hash,
            new DataEncryptor.EncryptedData { Data = cipherText, Nounce = nounce, Tag = tag });

        var storedVault = VaultType.Deserialize(plainText);
        Assert.NotNull(storedVault);

        foreach (var (id, pass) in vault.Passwords)
        {
            Assert.Equal(pass, storedVault.Passwords[id]);
        }
    }
}