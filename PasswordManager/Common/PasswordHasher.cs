using System;
using System.Security.Cryptography;

namespace PasswordManager.Common
{
    /// <summary>
    ///     This class provides a method to securely hash a password.
    /// </summary>
    public class PasswordHasher : IDisposable
    {
        // Cryptographically secure random number generation
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;
        
        /// <summary>
        ///     Create a new instance of 'PasswordHasher'
        /// </summary>
        public PasswordHasher()
        {
            _cryptoServiceProvider = new RNGCryptoServiceProvider();
        }
        
        /// <summary>
        ///     Generate a hash for the provided password using a 32-byte random salt
        ///     alongside PBKDF2-HMAC-SHA512 with 200,000 iterations.
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <param name="hashLength">The hash length</param>
        /// <returns>The hashed password</returns>
        public HashedResult HashPassword(string password, int hashLength)
        {
            // Generate a secure random salt
            var salt = new byte[Constants.SaltSize];
            _cryptoServiceProvider.GetBytes(salt);
            
            // C# / .NET Implementation of PBKDF2
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 200_000, HashAlgorithmName.SHA512);
            return new HashedResult
            {
                Salt = salt,
                Hash = pbkdf2.GetBytes(hashLength)
            };
        }
        
        /// <summary>
        ///     Generate a hash for the provided password using a provided salt
        ///     alongside PBKDF2-HMAC-SHA512 with 200,000 iterations.
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <param name="salt">A salt to use alongside the password</param>
        /// <param name="hashLength">The hash length</param>
        /// <returns>The hashed password</returns>
        public HashedResult HashPassword(string password, byte[] salt, int hashLength)
        {
            // C# / .NET Implementation of PBKDF2
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 200_000, HashAlgorithmName.SHA512);
            return new HashedResult
            {
                Salt = salt,
                Hash = pbkdf2.GetBytes(hashLength)
            };
        }
        
        /// <summary>
        ///     Dispose resources 
        /// </summary>
        public void Dispose()
        {
            _cryptoServiceProvider.Dispose();
            GC.SuppressFinalize(this);
        }

        public struct HashedResult
        {
            public byte[] Salt;
            public byte[] Hash;
        }
    }
}