using PasswordManager.Common;
using PasswordManager.Types;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace PasswordManager
{
    public class Vault : IDisposable
    {
        // Cryptographically secure services
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;

        private readonly PasswordGenerator _passwordGenerator;
        private readonly PasswordHasher _passwordHasher;
        private readonly DataEncryptor _dataEncryptor;

        // The internal vault
        private VaultType? _vaultInternal;
        
        // The key (hash) and salt and used to encrypt and decrypt the vault
        private PasswordHasher.HashedResult? _key;

        // Where the vault is located
        private readonly string _filePath;

        /// <summary>
        ///     Creates a new vault at the specified file location. Encrypts the vault
        ///     with the provided password.
        /// </summary>
        /// <param name="filePath">File name/location to store the vault</param>
        /// <param name="password">The password to encrypt the vault</param>
        /// <returns>An opened vault</returns>
        public static async Task<Vault> CreateVaultAsync(string filePath, string password)
        {
            var vault = new Vault(filePath);
            await vault.CreateVaultInternalAsync(password);
            return vault;
        }

        public static async Task<Vault> OpenVaultAsync(string filePath, string password)
        {
            var vault = new Vault(filePath);
            await vault.OpenVaultInternalAsync(password);
            return vault;
        }

        private Vault(string filePath)
        {
            // Use the same RNG Crypto service provider for all modules
            _cryptoServiceProvider = new RNGCryptoServiceProvider();
            _passwordGenerator = new PasswordGenerator(_cryptoServiceProvider);
            _passwordHasher = new PasswordHasher(_cryptoServiceProvider);
            _dataEncryptor = new DataEncryptor(_cryptoServiceProvider);

            _filePath = filePath;
        }

        /// <summary>
        ///     Internally, creating a vault create a new internal vault object, saves it,
        ///     and then opens it again.
        /// </summary>
        /// <param name="password"></param>
        private async Task CreateVaultInternalAsync(string password)
        {
            // Create a new empty vault
            _vaultInternal = new VaultType { Passwords = new Dictionary<string, string>() };

            // Hash the provided password and store it so vault saving works
            _key = _passwordHasher.HashPassword(password, Constants.KeySize);

            // Attempt to save this vault (this also ensures the file location is correct)
            await SaveVaultAsync();

            // Now open this vault again to ensure everything is setup correctly
            await OpenVaultInternalAsync(password);
        }

        private async Task OpenVaultInternalAsync(string password)
        {
            // Read and unpack the file
            var rawFileContents = await File.ReadAllBytesAsync(_filePath);
            var (salt, rawData) = DataPacker.UnpackData(rawFileContents);

            // Hash the provided password with the vault salt
            _key = _passwordHasher.HashPassword(password, salt, Constants.KeySize);

            // Using this key, attempt to decrypt the vault
            var decryptedData = _dataEncryptor.Decrypt(_key.Value.Hash, rawData);

            // We now have an internal vault
            _vaultInternal = VaultType.Deserialize(decryptedData);
            if (_vaultInternal == null)
                throw new Exception("Vault was null after deserialize");
        }

        /// <summary>
        ///     Returns a list of password entries (the unique key of a password), this key
        ///     can then be used to retrieve a specifid password
        /// </summary>
        /// <returns></returns>
        public IEnumerable<string> GetPasswordEntries()
        {
            AssertValid();

            return _vaultInternal!.Passwords.Select(x => x.Key);
        }

        /// <summary>
        ///     Create a new password entry with the specified key and
        ///     random password length.
        /// </summary>
        /// <param name="identifier">The identifier to store the password under</param>
        /// <param name="randomPasswordLength">The length to make this password</param>
        public void CreateRandomPassword(string identifier, int randomPasswordLength)
        {
            AssertValid();
            
            if (string.IsNullOrEmpty(identifier))
                throw new VaultException(VaultExceptionReason.InvalidIdentifier);

            var randomPassword = _passwordGenerator.GeneratePassword(randomPasswordLength);
            CreatePassword(identifier, randomPassword);
        }

        public void CreatePassword(string identifier, string password)
        {
            AssertValid();

            if (string.IsNullOrEmpty(identifier))
                throw new VaultException(VaultExceptionReason.InvalidIdentifier);
            
            if (string.IsNullOrEmpty(password))
                throw new VaultException(VaultExceptionReason.InvalidPassword);

            if (_vaultInternal!.Passwords.ContainsKey(identifier))
                throw new VaultException(VaultExceptionReason.IdentifierAlreadyExists);
            
            _vaultInternal!.Passwords.Add(identifier, password);
        }

        /// <summary>
        ///     Get a password that is stored in the vault. Throws an exception if
        ///     the password cannot be found.
        /// </summary>
        /// <param name="identifier">An identifier for the password</param>
        /// <returns>The password for the supplied identifier</returns>
        /// <exception cref="VaultException">The identifier does not exist or is invalid</exception>
        public string GetPassword(string identifier)
        {
            AssertValid();
            
            if (string.IsNullOrEmpty(identifier))
                throw new VaultException(VaultExceptionReason.InvalidIdentifier);

            var result = _vaultInternal!.Passwords.TryGetValue(identifier, out var password);
            if (!result || string.IsNullOrEmpty(password))
                throw new VaultException(VaultExceptionReason.IdentifierNotExist);

            return password;
        }

        /// <summary>
        ///     Save the vault to file
        /// </summary>
        public async Task SaveVaultAsync()
        {
            AssertValid();

            // Encrypt the internal vault using the provided key hash
            // This generates a new authentication tag and nounce each time
            var encryptedData = _dataEncryptor.Encrypt(_key!.Value.Hash, _vaultInternal!.Serialize());

            // Now pack the encrypted data, alongside the salt so it can be saved to disk
            var packedData = DataPacker.PackData(_key.Value.Salt, encryptedData);

            // Now write to file
            await using var stream = File.Open(_filePath, FileMode.Create, FileAccess.Write);
            await stream.WriteAsync(packedData);
        }

        /// <summary>
        ///     This method ensures that the vault is in a valid state. Throws an exception if not.
        /// </summary>
        /// <exception cref="VaultException">Why the vault is not in a valid state</exception>
        private void AssertValid()
        {
            if (_vaultInternal == null)
                throw new VaultException(VaultExceptionReason.NotValid);

            if (_key == null)
                throw new VaultException(VaultExceptionReason.MissingKey);
        }

        public void Dispose()
        {
            _vaultInternal = null;
            _key = null;

            _dataEncryptor.Dispose();
            _passwordHasher.Dispose();
            _passwordGenerator.Dispose();
            _cryptoServiceProvider.Dispose();
            
            GC.SuppressFinalize(this);
        }
    }
}