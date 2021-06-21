using PasswordManager.Types;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace PasswordManager.Tests
{
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
            var myVault =  await Vault.CreateVaultAsync("vault_test_2.vault", "Pa$$w0rd");
            myVault.CreatePassword("youtube", "Pa$$w0rd12345");

            Assert.Throws<VaultException>(() => myVault.GetPassword("invalid-id"));
            Assert.Throws<VaultException>(() => myVault.GetPassword(null));

            Assert.Single(myVault.GetPasswordEntries());

            Assert.Throws<VaultException>(() => myVault.CreatePassword(null, null));
            Assert.Throws<VaultException>(() => myVault.CreatePassword("valid-id", null));
            Assert.Throws<VaultException>(() => myVault.CreatePassword(null, "valid-password"));

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
            var _vaultInternal = myVault.GetType().GetField("_vaultInternal", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            _vaultInternal.SetValue(myVault, null);

            Assert.Throws<VaultException>(() => myVault.GetPasswordEntries());

            await Assert.ThrowsAsync<VaultException>(async () => await myVault.SaveVaultAsync());

            myVault.Dispose();
        }

        [Fact]
        public async Task TestInternalVaultKeyTampering()
        {
            var myVault = await Vault.CreateVaultAsync("vault_test_3.vault", "Pa$$w0rd");

            // Bad reflection!
            var _key = myVault.GetType().GetField("_key", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            _key.SetValue(myVault, null);

            Assert.Throws<VaultException>(() => myVault.GetPasswordEntries());

            await Assert.ThrowsAsync<VaultException>(async () => await myVault.SaveVaultAsync());

            myVault.Dispose();
        }
    }
}