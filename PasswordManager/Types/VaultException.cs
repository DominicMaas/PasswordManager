using PasswordManager.Common;

namespace PasswordManager.Types;

public class VaultException : Exception
{
    public VaultExceptionReason Reason { get; }

    public VaultException(VaultExceptionReason reason, Exception? innerException = null) : base(MessageFromReason(reason), innerException)
    {
        Reason = reason;
    }

    private static string MessageFromReason(VaultExceptionReason reason)
    {
        return reason switch
        {
            VaultExceptionReason.NotValid or VaultExceptionReason.MissingKey => "The vault was not loaded correctly. Please close the application and try again",
            VaultExceptionReason.IdentifierAlreadyExists => "The supplied password identifier already exists. Please choose a different identifier or delete the existing identifier",
            VaultExceptionReason.IdentifierNotExist => "Cannot find a password within this vault with the supplied identifier.",
            VaultExceptionReason.InvalidIdentifier => "The supplied identifier is invalid, please try again. The identifier must be in-between 1 and 255 characters",
            VaultExceptionReason.InvalidPassword => $"The supplied password is invalid, please try again. The password must be in-between {PasswordGenerator.MinimumPossiblePasswordLength} and {PasswordGenerator.MaximumPossiblePasswordLength} characters long",
            VaultExceptionReason.InvalidMasterPassword => "The master password that you have entered is incorrect or the vault has been tampered with",
            VaultExceptionReason.InvalidVaultPath => "The supplied vault location is invalid. Please make sure the path exists and try again",
            VaultExceptionReason.NoVault => "Could not find a vault at the supplied file location",
            VaultExceptionReason.IoError => "An unknown IO error has occurred",
            _ => "An unknown error has occurred"
        };
    }
}

public enum VaultExceptionReason
{
    NotValid,
    MissingKey,
    IdentifierAlreadyExists,
    IdentifierNotExist,
    InvalidIdentifier,
    InvalidPassword,
    InvalidMasterPassword,
    InvalidVaultPath,
    NoVault,
    IoError
}