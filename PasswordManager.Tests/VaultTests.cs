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
        }
    }
}