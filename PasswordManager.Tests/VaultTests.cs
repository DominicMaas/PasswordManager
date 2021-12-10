using PasswordManager.Common;
using PasswordManager.Types;
using System.Runtime.InteropServices;
using Xunit;

namespace PasswordManager.Tests;

public class VaultTests
{
    [Fact]
    public async Task CreateVault()
    {
        var myVault = await Vault.CreateVaultAsync("vault_test.vault", "Pa$$w0rd");
        myVault.CreatePassword("youtube", "Pa$$w0rd12345");
        await myVault.SaveVaultAsync();

        // ----- Barrier ----- //

        using var existingVault = await Vault.OpenVaultAsync("vault_test.vault", "Pa$$w0rd");
        var storedPassword = existingVault.GetPassword("youtube");

        Assert.Equal("Pa$$w0rd12345", storedPassword);

        myVault.Dispose();
        existingVault.Dispose();
    }

    [Fact]
    public async Task TestGeneralFlow()
    {
        var myVault = await Vault.CreateVaultAsync("vault_test_2.vault", "Pa$$w0rd");
        myVault.CreatePassword("youtube", "Pa$$w0rd12345");

        Assert.Throws<VaultException>(() => myVault.GetPassword("invalid-id"));
        Assert.Throws<VaultException>(() => myVault.GetPassword(null!));

        Assert.Single(myVault.GetPasswordEntries());

        Assert.Throws<VaultException>(() => myVault.CreatePassword(null!, null!));
        Assert.Throws<VaultException>(() => myVault.CreatePassword("valid-id", null!));
        Assert.Throws<VaultException>(() => myVault.CreatePassword(null!, "valid-password"));

        Assert.Throws<VaultException>(() => myVault.CreatePassword("youtube", "my-new-password"));
        myVault.CreatePassword("youtube-2", "my-new-password");

        Assert.Throws<VaultException>(() => myVault.CreateRandomPassword("youtube", 40));
        myVault.CreateRandomPassword("youtube-3", 40);

        Assert.Equal(3, myVault.GetPasswordEntries().Count());

        foreach (var password in myVault.GetPasswordEntries())
        {
            Assert.NotNull(myVault.GetPassword(password));
        }

        myVault.DeletePassword("youtube-2");
        myVault.DeletePassword("youtube-3");

        Assert.Single(myVault.GetPasswordEntries());

        Assert.Throws<VaultException>(() => myVault.DeletePassword(null));
        Assert.Throws<VaultException>(() => myVault.DeletePassword("i do not exist"));

        myVault.Dispose();
    }

    [Fact]
    public async Task TestGeneralExtremeLimits()
    {
        var myVault = await Vault.CreateVaultAsync("vault_test_3.vault", "Pa$$w0rd");

        // Extremely long identifier
        Assert.Throws<VaultException>(() => myVault.CreatePassword("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.", "Pa$$w0rd12345"));

        // Password too short
        Assert.Throws<VaultException>(() => myVault.CreatePassword("test-short", "abc"));

        // Password too long
        Assert.Throws<VaultException>(() => myVault.CreatePassword("test-long", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."));

        // Identifier is just spaces
        Assert.Throws<VaultException>(() => myVault.CreatePassword("      ", "abc"));

        // Password is just spaces
        Assert.Throws<VaultException>(() => myVault.CreatePassword("test-spaces", "     "));

        // Random password is out of bounds
        Assert.Throws<VaultException>(() => myVault.CreateRandomPassword("test-random-short", 4));
        Assert.Throws<VaultException>(() => myVault.CreateRandomPassword("test-random-long", 500));

        myVault.Dispose();
    }

    [Fact]
    public async Task TestInternalVaultReflectionTampering()
    {
        var myVault = await Vault.CreateVaultAsync("vault_test_3.vault", "Pa$$w0rd");

        // Bad reflection!
        var vaultInternal = myVault.GetType().GetField("_vaultInternal", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        vaultInternal!.SetValue(myVault, null);

        Assert.Throws<VaultException>(() => myVault.GetPasswordEntries());

        await Assert.ThrowsAsync<VaultException>(async () => await myVault.SaveVaultAsync());

        myVault.Dispose();
    }

    [Fact]
    public async Task TestInternalVaultKeyTampering()
    {
        var myVault = await Vault.CreateVaultAsync("vault_test_4.vault", "Pa$$w0rd");

        // Bad reflection!
        var key = myVault.GetType().GetField("_key", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        key!.SetValue(myVault, null);

        Assert.Throws<VaultException>(() => myVault.GetPasswordEntries());

        await Assert.ThrowsAsync<VaultException>(async () => await myVault.SaveVaultAsync());

        myVault.Dispose();
    }

    [Fact]
    public async Task TestVaultInvalidPassword()
    {
        {
            var myVault = await Vault.CreateVaultAsync("vault_test_5.vault", "Pa$$w0rd");
            myVault.CreateRandomPassword("twitter", 32);
            myVault.CreateRandomPassword("youtube", 32);
            myVault.CreateRandomPassword("github", 32);
            await myVault.SaveVaultAsync();
            myVault.Dispose();
        }

        await Assert.ThrowsAsync<VaultException>(async () => await Vault.OpenVaultAsync("vault_test_5.vault", "NotTheSamePassword"));
    }

    [Fact]
    public async Task TestVaultCipherTamper()
    {
        {
            var myVault = await Vault.CreateVaultAsync("vault_test_6.vault", "Pa$$w0rd6");
            myVault.CreateRandomPassword("twitter", 32);
            myVault.CreateRandomPassword("youtube", 32);
            myVault.CreateRandomPassword("github", 32);
            await myVault.SaveVaultAsync();
            myVault.Dispose();
        }

        {
            var rawFileContents = await File.ReadAllBytesAsync("vault_test_6.vault");
            var (salt, rawData) = DataPacker.UnpackData(rawFileContents);

            rawData.Data[31] = 0xDA;
            rawData.Data[32] = 0xEB;
            rawData.Data[33] = 0xFC;

            var packedData = DataPacker.PackData(salt, rawData);
            await File.WriteAllBytesAsync("vault_test_6.vault", packedData);
        }

        {
            await Assert.ThrowsAsync<VaultException>(async () => await Vault.OpenVaultAsync("vault_test_6.vault", "Pa$$w0rd6"));
        }
    }

    [Fact]
    public async Task TestVaultSaltTamper()
    {
        {
            var myVault = await Vault.CreateVaultAsync("vault_test_7.vault", "Pa$$w0rd7");
            myVault.CreateRandomPassword("twitter", 32);
            myVault.CreateRandomPassword("youtube", 32);
            myVault.CreateRandomPassword("github", 32);
            await myVault.SaveVaultAsync();
            myVault.Dispose();
        }

        {
            var rawFileContents = await File.ReadAllBytesAsync("vault_test_7.vault");
            var (salt, rawData) = DataPacker.UnpackData(rawFileContents);

            salt[0] = 0xDA;
            salt[1] = 0xEB;
            salt[2] = 0xFC;

            var packedData = DataPacker.PackData(salt, rawData);
            await File.WriteAllBytesAsync("vault_test_7.vault", packedData);
        }

        {
            await Assert.ThrowsAsync<VaultException>(async () => await Vault.OpenVaultAsync("vault_test_7.vault", "Pa$$w0rd7"));
        }
    }

    [Fact]
    public async Task TestVaultNounceTamper()
    {
        {
            var myVault = await Vault.CreateVaultAsync("vault_test_8.vault", "Pa$$w0rd8");
            myVault.CreateRandomPassword("twitter", 32);
            myVault.CreateRandomPassword("youtube", 32);
            myVault.CreateRandomPassword("github", 32);
            await myVault.SaveVaultAsync();
            myVault.Dispose();
        }

        {
            var rawFileContents = await File.ReadAllBytesAsync("vault_test_8.vault");
            var (salt, rawData) = DataPacker.UnpackData(rawFileContents);

            rawData.Nounce[0] = 0xDA;
            rawData.Nounce[1] = 0xEB;
            rawData.Nounce[2] = 0xFC;

            var packedData = DataPacker.PackData(salt, rawData);
            await File.WriteAllBytesAsync("vault_test_8.vault", packedData);
        }

        {
            await Assert.ThrowsAsync<VaultException>(async () => await Vault.OpenVaultAsync("vault_test_8.vault", "Pa$$w0rd8"));
        }
    }

    [Fact]
    public async Task TestVaultAuthTagTamper()
    {
        {
            var myVault = await Vault.CreateVaultAsync("vault_test_9.vault", "Pa$$w0rd9");
            myVault.CreateRandomPassword("twitter", 32);
            myVault.CreateRandomPassword("youtube", 32);
            myVault.CreateRandomPassword("github", 32);
            await myVault.SaveVaultAsync();
            myVault.Dispose();
        }

        {
            var rawFileContents = await File.ReadAllBytesAsync("vault_test_9.vault");
            var (salt, rawData) = DataPacker.UnpackData(rawFileContents);

            rawData.Tag[0] = 0xDA;
            rawData.Tag[1] = 0xEB;
            rawData.Tag[2] = 0xFC;

            var packedData = DataPacker.PackData(salt, rawData);
            await File.WriteAllBytesAsync("vault_test_9.vault", packedData);
        }

        {
            await Assert.ThrowsAsync<VaultException>(async () => await Vault.OpenVaultAsync("vault_test_9.vault", "Pa$$w0rd9"));
        }
    }

    [Fact]
    public async Task TestInvalidFileLocations1()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            await Assert.ThrowsAsync<VaultException>(async () => await Vault.CreateVaultAsync("A:\\what\\yyear\\is\\this\\??\\test.vault", "Pa$$w0rd9"));
        }
    }

    [Fact]
    public async Task TestInvalidFileLocations2()
    {
        await Assert.ThrowsAsync<VaultException>(async () => await Vault.CreateVaultAsync("testing/test.vault", "Pa$$w0rd9"));
    }

    [Fact]
    public async Task TestInvalidFileLocations3()
    {
        await Assert.ThrowsAsync<VaultException>(async () => await Vault.OpenVaultAsync("idontexist.vault", "Pa$$w0rd9"));
    }

    [Fact]
    public async Task TestVaultOpenAndSave()
    {
        var myVault = await Vault.CreateVaultAsync("vault_test_10.vault", "Pa$$w0rd10");
        myVault.CreateRandomPassword("twitter", 32);
        myVault.CreateRandomPassword("youtube", 32);
        myVault.CreateRandomPassword("github", 32);

        var rawFileContents = File.Open("vault_test_10.vault", FileMode.OpenOrCreate);

        await Assert.ThrowsAsync<VaultException>(async () => await myVault.SaveVaultAsync());

        rawFileContents.Close();

        await myVault.SaveVaultAsync();
    }
}