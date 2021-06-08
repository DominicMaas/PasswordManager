namespace PasswordManager
{
    public class Vault
    {
        public static Vault Create(string filename, string password)
        {
            return new Vault();
        }

        public static Vault Open(string filename, string password)
        {
            return new Vault();
        }
    }
}