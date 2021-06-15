using System.Threading.Tasks;
using Xunit;

namespace PasswordManager.Tests
{
    public class VaultTests
    {
        [Fact]
        public async Task CreateVault()
        {
            using var myVault = await Vault.CreateVaultAsync("vault_test.vault", "Pa$$w0rd");
          //  myVault.CreatePassword("youtube", "Pa$$w0rd12345");
        }
        
    }
}