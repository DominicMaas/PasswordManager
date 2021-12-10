using System.Security.Cryptography;

namespace PasswordManager.Common;

/// <summary>
///     The password generator allows the creation of cryptographically secure
///     random passwords between 8 and 80 characters.
/// </summary>
public static class PasswordGenerator
{
    // These are valid characters that may be used in the password
    private const string ValidPasswordCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_+=[]{};':<>?,./|\"\\~`";

    public const int MinimumPossiblePasswordLength = 8;
    public const int MaximumPossiblePasswordLength = 80;
    
    public static string GeneratePassword(int length)
    {
        // Guards
        if (length < MinimumPossiblePasswordLength) throw new ArgumentException($"Password length must be at least {MinimumPossiblePasswordLength} characters long", nameof(length));
        if (length > MaximumPossiblePasswordLength) throw new ArgumentException($"Password length must be less than or equal to {MaximumPossiblePasswordLength} characters long", nameof(length));

        // Converting to a char array for easy access
        var potentialPasswordChars = ValidPasswordCharacters.ToCharArray();

        var generatedResult = new char[length];

        var bytes = new byte[length * 8];
        RandomNumberGenerator.Fill(bytes);

        // There is a small bias due to the modulus operation not spreading the entire width of ulong equally into {NUMBER} chars.
        for (var i = 0; i < length; i++)
        {
            var value = BitConverter.ToUInt64(bytes, i * 8);
            generatedResult[i] = potentialPasswordChars[value % (uint)potentialPasswordChars.Length];
        }

        return new string(generatedResult);
    }
}