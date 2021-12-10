using System.Security.Cryptography;

namespace PasswordManager.Common;

public static class Constants
{
    public const int KeySize = 256 / 8;

    public const int SaltSize = 32;
    
    public static readonly int TagSize = AesGcm.TagByteSizes.MaxSize; // 16
    
    public static readonly int NounceSize = AesGcm.NonceByteSizes.MaxSize; // 12

    public static readonly int FixedPackedSize = SaltSize + TagSize + NounceSize;

    public static Range GetCipherTextRange(int cipherTextLength)
    {
        return new Range(0, cipherTextLength);
    }

    public static Range GetSaltRange(int cipherTextLength)
    {
        var r = GetCipherTextRange(cipherTextLength);
        return new Range(r.End, r.End.Value + SaltSize);
    }

    public static Range GetNounceRange(int cipherTextLength)
    {
        var r = GetSaltRange(cipherTextLength);
        return new Range(r.End, r.End.Value + NounceSize);
    }

    public static Range GetTagRange(int cipherTextLength)
    {
        var r = GetNounceRange(cipherTextLength);
        return new Range(r.End, r.End.Value + TagSize);
    }
}