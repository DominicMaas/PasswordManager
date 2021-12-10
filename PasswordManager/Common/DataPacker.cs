namespace PasswordManager.Common;

/// <summary>
///     A simple class that packs data ready for file write
/// </summary>
public static class DataPacker
{
    public static byte[] PackData(byte[] salt, DataEncryptor.EncryptedData data)
    {
        // Guard lengths
        if (salt.Length != Constants.SaltSize)
            throw new ArgumentException("Salt is expected to be 'Constants.SaltSize' in length", nameof(salt));

        if (data.Nounce.Length != Constants.NounceSize)
            throw new ArgumentException("Nounce is expected to be 'Constants.NounceSize' in length", nameof(data.Nounce));

        if (data.Tag.Length != Constants.TagSize)
            throw new ArgumentException("Tag is expected to be 'Constants.TagSize' in length", nameof(data.Tag));

        var cipherTextLength = data.Data.Length;
        var dataLength = cipherTextLength + Constants.FixedPackedSize;
        var encryptedData = new byte[dataLength].AsSpan();

        data.Data.CopyTo(encryptedData[Constants.GetCipherTextRange(cipherTextLength)]);

        salt.CopyTo(encryptedData[Constants.GetSaltRange(cipherTextLength)]);
        data.Nounce.CopyTo(encryptedData[Constants.GetNounceRange(cipherTextLength)]);
        data.Tag.CopyTo(encryptedData[Constants.GetTagRange(cipherTextLength)]);

        return encryptedData.ToArray();
    }

    public static (byte[] salt, DataEncryptor.EncryptedData data) UnpackData(byte[] input)
    {
        var cipherTextLength = input.Length - Constants.FixedPackedSize;

        // The input data
        var inputSpan = input.AsSpan();

        // Where we will store the data
        var cipherText = new byte[cipherTextLength];
        var salt = new byte[Constants.SaltSize];
        var nounce = new byte[Constants.NounceSize];
        var tag = new byte[Constants.TagSize];

        inputSpan[Constants.GetCipherTextRange(cipherTextLength)].CopyTo(cipherText);
        inputSpan[Constants.GetSaltRange(cipherTextLength)].CopyTo(salt);
        inputSpan[Constants.GetNounceRange(cipherTextLength)].CopyTo(nounce);
        inputSpan[Constants.GetTagRange(cipherTextLength)].CopyTo(tag);

        return (salt, new DataEncryptor.EncryptedData
        {
            Data = cipherText,
            Nounce = nounce,
            Tag = tag
        });
    }
}