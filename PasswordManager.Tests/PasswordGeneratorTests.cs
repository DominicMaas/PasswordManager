using PasswordManager.Common;
using System;
using System.Collections.Generic;
using System.Linq;
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
        using var passwordGenerator = new PasswordGenerator();
        Assert.Throws<ArgumentException>(() => passwordGenerator.GeneratePassword(5));
    }

    [Fact]
    public void LengthTooLong()
    {
        using var passwordGenerator = new PasswordGenerator();
        Assert.Throws<ArgumentException>(() => passwordGenerator.GeneratePassword(100));
    }

    [Fact]
    public void SingleGeneration()
    {
        using var passwordGenerator = new PasswordGenerator();
        passwordGenerator.GeneratePassword(80);
    }

    [Fact]
    public void MassGeneration()
    {
        // Keep track of counts to see distribution
        var dict = new Dictionary<char, int>();

        using var passwordGenerator = new PasswordGenerator();
        for (var i = 0; i < 5_000_000; i++) // 5 million passwords
        {
            var pass = passwordGenerator.GeneratePassword(80);
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