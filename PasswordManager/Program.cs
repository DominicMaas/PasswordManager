using PasswordManager.Common;
using PasswordManager.Types;
using System.Text;

namespace PasswordManager;

/// <summary>
///     The "GUI" for this program is created as a state like machine.
/// </summary>
public class Program
{
    public static async Task Main(string[] args)
    {
        var result = await WelcomeState();
        Environment.Exit(result ? 0 : -1);
    }

    /// <summary>
    ///     This state welcomes the user, and allows them to choose an option
    ///     to continue using the application
    /// </summary>
    /// <returns></returns>
    private static async Task<bool> WelcomeState()
    {
        WriteHeader();
        var key = AskUserForOptions("Please select an action:", new[]
        {
            (1, "Open a vault"),
            (2, "Create a vault"),
            (3, "Exit application")
        });

        return key switch
        {
            1 => await OpenVaultState(),
            2 => await CreateVaultState(),
            3 => true,
            _ => await WelcomeState(),
        };
    }

    /// <summary>
    ///     This state allows the user to open an existing vault
    /// </summary>
    private static async Task<bool> OpenVaultState()
    {
        WriteHeader();

        // User parameters
        var filePath = AskUserForInput("Please enter the name/path of the vault you wish to open:");
        var password = AskUserForPassword("Please enter your master password:");

        // Attempt to open the vault (TODO: Deal with null values here, but the vault also deals with them though so not super important)
        Vault? v = null;
        if (!await HandleVaultException(async () => { v = await Vault.OpenVaultAsync(filePath, password); }))
            return await OpenVaultState();

        return await VaultRunningState(v!); // The vault cannot be null at this point
    }

    /// <summary>
    ///     This state allows the user to create a new empty vault
    /// </summary>
    private static async Task<bool> CreateVaultState()
    {
        WriteHeader();

        // User parameters
        var filePath = AskUserForInput("Please enter a unique name for your vault:");
        var password = AskUserForPassword("Please enter a master password which will be used to encrypt your vault:");

        // Attempt to create a vault (TODO: Deal with null values here, the vault also deals with them though)
        Vault? v = null;
        if (!await HandleVaultException(async () => { v = await Vault.CreateVaultAsync(filePath, password); }))
            return await CreateVaultState();

        return await VaultRunningState(v!); // The vault cannot be null at this point
    }

    /// <summary>
    ///     This state handles all core vault operations while the user is in a vault
    /// </summary>
    /// <param name="vault">The current vault the user is in</param>
    private static async Task<bool> VaultRunningState(Vault vault)
    {
        WriteHeader();
        Console.WriteLine($"Vault: {vault.FilePath}\n");

        var key = AskUserForOptions("Please select an action:", new[]
        {
            (1, "List stored passwords"),
            (2, "Store a new password"),
            (3, "Save changes & exit vault"),
            (4, "Exit vault without saving changes")
        });

        switch (key)
        {
            case 1: // View passwords
                return await PasswordsListState(vault);

            case 2: // Store a password
                return await StorePasswordState(vault);

            case 3: // Saving the vault and quiting
                if (await HandleVaultException(async () => await vault.SaveVaultAsync()))
                {
                    vault.Dispose();
                    return await WelcomeState();
                }
                else
                {
                    // Something went wrong, the user has been told, return back to the vault (where the user can try again)
                    return await VaultRunningState(vault);
                }

            case 4: // Return to the main menu
                vault.Dispose();
                return await WelcomeState();

            default: // Invalid, restore current state
                return await VaultRunningState(vault);
        }
    }

    #region Viewing Passwords

    private static async Task<bool> PasswordsListState(Vault vault)
    {
        WriteHeader();
        Console.WriteLine($"Vault: {vault.FilePath}\n\nPassword Entries:");

        var passwordEntries = new List<string>();
        if (!HandleVaultException(() => passwordEntries = vault.GetPasswordEntries().ToList()))
            return await VaultRunningState(vault);

        if (passwordEntries.Any())
        {
            foreach (var entry in passwordEntries)
            {
                Console.WriteLine(entry);
            }
        }
        else
        {
            Console.WriteLine("There are no password entries in this vault!");
        }

        var key = AskUserForOptionsRaw("\nPlease select an action or type in a password identifier to view:", new[]
        {
            (1, "Go back"),
        }, out var identifier);

        return key switch
        {
            1 => await VaultRunningState(vault),
            _ => await ViewPasswordState(vault, identifier),
        };
    }

    private static async Task<bool> ViewPasswordState(Vault vault, string? identifier)
    {
        WriteHeader();
        Console.WriteLine($"Vault: {vault.FilePath}\n\nPassword Entry: {identifier}");

        if (string.IsNullOrEmpty(identifier))
            return await PasswordsListState(vault);

        string? password = null;

        if (!HandleVaultException(() => password = vault.GetPassword(identifier)) || string.IsNullOrEmpty(password))
            return await PasswordsListState(vault);

        Console.WriteLine(password);

        Console.WriteLine("\nPress any key to go back...");
        Console.ReadKey();

        return await PasswordsListState(vault);
    }

    #endregion Viewing Passwords

    #region Storing Passwords

    private static async Task<bool> StorePasswordState(Vault vault)
    {
        WriteHeader();
        Console.WriteLine($"Vault: {vault.FilePath}\n");

        var key = AskUserForOptions("Please select an action:", new[]
        {
            (1, "Generate & store a random password"),
            (2, "Store a custom password"),
            (3, "Go back")
        });

        return key switch
        {
            1 => await GenerateAndStoreRandomPasswordState(vault),
            2 => await StoreCustomPasswordState(vault),
            3 => await VaultRunningState(vault),
            _ => await StorePasswordState(vault),
        };
    }

    private static async Task<bool> GenerateAndStoreRandomPasswordState(Vault vault, string? identifier = null)
    {
        WriteHeader();
        Console.WriteLine($"Vault: {vault.FilePath}\n");

        // Parse identifier if not provided
        identifier = string.IsNullOrEmpty(identifier) ? AskUserForInput("Please enter a unique identifier for your password:") : identifier;

        // If the user enters nothing, chuck them back to the asking state
        if (string.IsNullOrEmpty(identifier))
            return await GenerateAndStoreRandomPasswordState(vault);

        // Get the password from the user
        var userInput = AskUserForInput($"[{identifier}] How many characters would you like your random password to be ({PasswordGenerator.MinimumPossiblePasswordLength}-{PasswordGenerator.MaximumPossiblePasswordLength})?");

        // Make sure the user actually entered a valid number / anything and within bounds
        if (string.IsNullOrEmpty(userInput)
            || !int.TryParse(userInput, out var passwordLength)
            || passwordLength > PasswordGenerator.MaximumPossiblePasswordLength
            || passwordLength < PasswordGenerator.MinimumPossiblePasswordLength)
        {
            Console.WriteLine($"Invalid number! Please enter a number between {PasswordGenerator.MinimumPossiblePasswordLength} and {PasswordGenerator.MaximumPossiblePasswordLength}. Press any key to try again.");
            Console.ReadKey();
            return await GenerateAndStoreRandomPasswordState(vault, identifier);
        }

        // If not successful, send the user back
        if (!HandleVaultException(() => vault.CreateRandomPassword(identifier, passwordLength)))
            return await GenerateAndStoreRandomPasswordState(vault);

        Console.WriteLine($"A random password has been stored under the identifier: {identifier}");
        var key = AskUserForOptions("What do you want to do now?", new[]
        {
            (1, "Store another password"),
            (2, "Go back to vault"),
        });

        return key switch
        {
            1 => await StorePasswordState(vault),
            _ => await VaultRunningState(vault)
        };
    }

    private static async Task<bool> StoreCustomPasswordState(Vault vault, string? identifier = null)
    {
        WriteHeader();
        Console.WriteLine($"Vault: {vault.FilePath}\n");

        // Parse identifier if not provided
        identifier = string.IsNullOrEmpty(identifier) ? AskUserForInput("Please enter a unique identifier for your password:") : identifier;

        // If the user enters nothing, chuck them back to the asking state
        if (string.IsNullOrEmpty(identifier))
            return await StoreCustomPasswordState(vault);

        // Get the password
        var password = AskUserForPassword("Please enter your password for this identifier:");

        // If the user enters nothing, chuck them back to the asking state
        if (string.IsNullOrEmpty(password))
            return await StoreCustomPasswordState(vault, identifier);

        // If not successful, send the user back
        if (!HandleVaultException(() => vault.CreatePassword(identifier, password)))
            return await StoreCustomPasswordState(vault);

        Console.WriteLine($"Your password has been stored under the identifier: {identifier}");
        var key = AskUserForOptions("What do you want to do now?", new[]
        {
            (1, "Store another password"),
            (2, "Go back to vault"),
        });

        return key switch
        {
            1 => await StorePasswordState(vault),
            _ => await VaultRunningState(vault)
        };
    }

    #endregion Storing Passwords

    #region Helpers

    private static void WriteHeader()
    {
        Console.Clear();
        Console.WriteLine("||======================================||");
        Console.WriteLine("||     Password Manager Application     ||");
        Console.WriteLine("||======================================||");
        Console.WriteLine("");
    }

    private static string? AskUserForInput(string? message = null)
    {
        if (!string.IsNullOrEmpty(message))
        {
            Console.WriteLine(message);
        }

        Console.Write("> ");
        return Console.ReadLine()?.TrimStart('>', ' ');
    }

    private static string? AskUserForPassword(string? message = null)
    {
        if (!string.IsNullOrEmpty(message))
        {
            Console.WriteLine(message);
        }

        Console.Write("> ");

        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }
            else if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    Console.Write("\b \b");
                }
            }
            else if (key.KeyChar != '\u0000')
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
        }

        Console.WriteLine();
        return password.ToString();
    }

    /// <summary>
    ///      A wrapper around asking the user for options for certain tasks
    /// </summary>
    /// <param name="message"></param>
    /// <param name="options"></param>
    /// <returns></returns>
    private static int AskUserForOptions(string message, IEnumerable<(int, string)> options)
    {
        return AskUserForOptionsRaw(message, options, out var _);
    }

    /// <summary>
    ///      A raw wrapper around asking the user for options for certain tasks. Also provides the
    ///      raw entered input from the user.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="options"></param>
    /// <param name="rawInput"></param>
    /// <returns></returns>
    private static int AskUserForOptionsRaw(string message, IEnumerable<(int, string)> options, out string? rawInput)
    {
        Console.WriteLine(message);
        foreach (var (keyNumber, description) in options)
        {
            Console.WriteLine($"{keyNumber}) {description}");
        }

        rawInput = AskUserForInput();
        if (!string.IsNullOrEmpty(rawInput) && int.TryParse(rawInput, out var choice))
            return choice;

        return -1;
    }

    /// <summary>
    ///     Run a vault command in the callback, exceptions will be handled, printed
    ///     to the user, where the user will then be prompted to try again. If this method
    ///     returns false, rerun the current state, otherwise continue.
    /// </summary>
    /// <param name="action"></param>
    /// <returns>True if the state should continue, false if it should be re-run</returns>
    private static bool HandleVaultException(Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (VaultException ex)
        {
            var errorMessage = ex.Message;

            if (ex.Reason == VaultExceptionReason.IoError && ex.InnerException != null)
                errorMessage += " " + ex.InnerException.Message;

            Console.WriteLine(errorMessage);
            Console.WriteLine("Press any key to continue.");
            Console.ReadKey();

            return false;
        }
    }

    private static async Task<bool> HandleVaultException(Func<Task> action)
    {
        try
        {
            await action();
            return true;
        }
        catch (VaultException ex)
        {
            var errorMessage = ex.Message;

            if (ex.Reason == VaultExceptionReason.IoError && ex.InnerException != null)
                errorMessage += " " + ex.InnerException.Message;

            Console.WriteLine(errorMessage);
            Console.WriteLine("Press any key to continue.");
            Console.ReadKey();

            return false;
        }
    }

    #endregion Helpers
}