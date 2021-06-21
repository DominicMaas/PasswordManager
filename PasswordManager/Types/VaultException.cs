using PasswordManager.Common;
using System;

namespace PasswordManager.Types
{
    public class VaultException : Exception
    {
        public VaultExceptionReason Reason { get; }

        public VaultException(VaultExceptionReason reason) : base(MessageFromReason(reason))
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
                _ => "An unknown error has occured"
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
    }
}