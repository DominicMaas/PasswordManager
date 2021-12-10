using PasswordManager.Common;
using Xunit;
using Xunit.Abstractions;

namespace PasswordManager.Tests;

public class PasswordGeneratorTests
{
    private readonly ITestOutputHelper _outputHelper;

    public PasswordGeneratorTests(ITestOutputHelper outputHelper)
    {
        _outputHelper = outputHelper;
    }

    [Fact]
    public void LengthTooSmall()
    {
        Assert.Throws<ArgumentException>(() => PasswordGenerator.GeneratePassword(5));
    }

    [Fact]
    public void LengthTooLong()
    {
        Assert.Throws<ArgumentException>(() => PasswordGenerator.GeneratePassword(100));
    }

    [Fact]
    public void SingleGeneration()
    {
        PasswordGenerator.GeneratePassword(80);
    }

    [Fact]
    public void MassGeneration()
    {
        // Keep track of counts to see distribution
        var dict = new Dictionary<char, int>();

        for (var i = 0; i < 5_000_000; i++) // 5 million passwords
        {
            var pass = PasswordGenerator.GeneratePassword(80);
            foreach (var c in pass.ToCharArray())
            {
                if (dict.ContainsKey(c))
                {
                    dict[c] += 1;
                }
                else
                {
                    dict.Add(c, 1);
                }
            }
        }

        foreach (var (key, value) in dict.OrderBy(x => x.Key))
        {
            _outputHelper.WriteLine($"{key} : {value}");
        }
    }
}