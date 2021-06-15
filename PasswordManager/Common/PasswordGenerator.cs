using System;
using System.Security.Cryptography;

namespace PasswordManager.Common
{
    /// <summary>
    ///     The password generator allows the creation of cryptographically secure
    ///     random passwords between 8 and 80 characters.
    /// </summary>
    public class PasswordGenerator : IDisposable
    {
        // Cryptographically secure random number generation
        private readonly RNGCryptoServiceProvider _cryptoServiceProvider;

        // These are valid characters that may be used in the password
        private const string ValidPasswordCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_+=[]{};':<>?,./|\"\\~`";

        /// <summary>
        ///     Create a new instance of 'PasswordGenerator'
        /// </summary>
        public PasswordGenerator(RNGCryptoServiceProvider? cryptoServiceProvider = null)
        {
            _cryptoServiceProvider = cryptoServiceProvider ?? new RNGCryptoServiceProvider();
        }

        public string GeneratePassword(int length)
        {
            // Guards
            if (length < 8) throw new ArgumentException("Password length must be at least 8 characters long", nameof(length));
            if (length > 80) throw new ArgumentException("Password length must be less than or equal to 80 characters long", nameof(length));
            
            // Converting to a char array for easy access
            var potentialPasswordChars = ValidPasswordCharacters.ToCharArray();
            
            var generatedResult = new char[length];
            
            var bytes = new byte[length * 8];
            _cryptoServiceProvider.GetBytes(bytes);
            
            // There is a small bias due to the modulus operation not spreading the entire width of ulong equally into {NUMBER} chars. 
            for (var i = 0; i < length; i++)
            {
                var value = BitConverter.ToUInt64(bytes, i * 8);
                generatedResult[i] = potentialPasswordChars[value % (uint)potentialPasswordChars.Length];
            }

            return new string(generatedResult);
        }
        
        /// <summary>
        ///     Dispose resources 
        /// </summary>
        public void Dispose()
        {
            _cryptoServiceProvider?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}