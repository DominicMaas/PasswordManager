using System.Text.Json;

namespace PasswordManager.Types;

/// <summary>
///     Special class that contains all the data for the vault. Also contains
///     helper methods for serializing and deserializing the vault.
/// </summary>
public class VaultType
{
    public Dictionary<string, string> Passwords { get; set; } = new();

    public byte[] Serialize() => JsonSerializer.SerializeToUtf8Bytes(this);

    public static VaultType? Deserialize(byte[] data) => JsonSerializer.Deserialize<VaultType>(data);
}