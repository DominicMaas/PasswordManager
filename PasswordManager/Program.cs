using PasswordManager.Common;
using System;
using System.Collections.Generic;

namespace PasswordManager
{
    /// <summary>
    ///     The "GUI" for this program is created as a state like machine.
    /// </summary>
    public class Program
    {
        private readonly PasswordGenerator _passwordGenerator;

        public static void Main(string[] args) => new Program().Run();

        private Program()
        {
            _passwordGenerator = new PasswordGenerator();
        }

        private void Run()
        {
            var result = WelcomeState();
            Environment.Exit(result ? 0 : -1);
        }

        /// <summary>
        ///     This state welcomes the user, and allows them to choose an option
        ///     to continue using the application
        /// </summary>
        /// <returns></returns>
        private bool WelcomeState()
        {
            WriteHeader();
            var key = AskUserForOptions("Please select an action:", new[]
            {
                (1, "Open a vault"),
                (2, "Create a vault"),
                (3, "Generate a random password"),
                (4, "Exit application")
            });

            switch (key)
            {
                case 1:
                    return OpenVaultState();

                case 2:
                    return CreateVaultState();

                case 3:
                    return GenerateRandomPasswordState();

                case 4:
                    return true;

                default:
                    Console.WriteLine("Invalid option! Press any key to try again.");
                    Console.ReadKey();
                    return WelcomeState();
            }
        }

        private bool OpenVaultState()
        {
            WriteHeader();

            return true;
        }

        private bool CreateVaultState()
        {
            WriteHeader();
            return true;
        }

        private bool GenerateRandomPasswordState()
        {
            WriteHeader();
            var userInput = AskUserForInput("How many characters would you like your random password to be?");

            // Make sure the user actually entered a valid number / anything
            if (string.IsNullOrEmpty(userInput) || !int.TryParse(userInput, out var passwordLength))
            {
                Console.WriteLine("Invalid number! Please enter a number between 8 and 80. Press any key to try again.");
                Console.ReadKey();
                return GenerateRandomPasswordState();
            }

            // Ensure the password is within the bounds
            if (passwordLength > 80 || passwordLength < 8)
            {
                Console.WriteLine("Invalid number! Please enter a number between 8 and 80. Press any key to try again.");
                Console.ReadKey();
                return GenerateRandomPasswordState();
            }

            WriteHeader();
            Console.WriteLine($"Generating a password of length {passwordLength}...");

            var password = _passwordGenerator.GeneratePassword(passwordLength);

            WriteHeader();
            Console.WriteLine($"Generated a password of length {passwordLength}!");
            Console.WriteLine("Your password is:");

            Console.WriteLine(password);
            Console.WriteLine();

            var key = AskUserForOptions("What do you want to do now?", new[]
            {
                (1, "Generate another random password"),
                (2, "Go back to the main menu"),
                (3, "Exit application")
            });

            return key switch
            {
                1 => GenerateRandomPasswordState(),
                3 => true,
                _ => WelcomeState()
            };
        }

        // ----- Helpers ----- //
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

        /// <summary>
        ///      A wrapper around asking the user for options for certain tasks
        /// </summary>
        /// <param name="message"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        private static int AskUserForOptions(string message, IEnumerable<(int, string)> options)
        {
            Console.WriteLine(message);
            foreach (var (keyNumber, description) in options)
            {
                Console.WriteLine($"{keyNumber}) {description}");
            }

            var input = AskUserForInput();
            if (!string.IsNullOrEmpty(input) && int.TryParse(input, out var choice))
                return choice;

            return -1;
        }
    }
}