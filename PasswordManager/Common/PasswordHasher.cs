using System.Security.Cryptography;

namespace PasswordManager.Common;

/// <summary>
///     This class provides a method to securely hash a password.
/// </summary>
public static class PasswordHasher
{
    /// <summary>
    ///     Generate a hash for the provided password using a 32-byte random salt
    ///     alongside PBKDF2-HMAC-SHA512 with 200,000 iterations.
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <param name="hashLength">The hash length</param>
    /// <returns>The hashed password</returns>
    public static HashedResult HashPassword(string password, int hashLength)
    {
        // Generate a secure random salt
        var salt = new byte[Constants.SaltSize];
        RandomNumberGenerator.Fill(salt);

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
    public static HashedResult HashPassword(string password, byte[] salt, int hashLength)
    {
        // C# / .NET Implementation of PBKDF2
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 200_000, HashAlgorithmName.SHA512);
        return new HashedResult
        {
            Salt = salt,
            Hash = pbkdf2.GetBytes(hashLength)
        };
    }
    
    public struct HashedResult
    {
        public byte[] Salt;
        public byte[] Hash;
    }
}