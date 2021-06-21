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
                VaultExceptionReason.InvalidIdentifier => "The supplied identifier is invalid, please try again",
                VaultExceptionReason.InvalidPassword => "The supplied password is invalid, please try again",
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
        InvalidPassword
    }
}