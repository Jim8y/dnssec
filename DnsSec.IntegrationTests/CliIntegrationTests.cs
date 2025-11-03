using System;
using System.IO;
using Xunit;

namespace DnsSec.IntegrationTests;

public class CliIntegrationTests
{
    [Fact]
    public void SignedDomain_ReturnsZeroAndReportsSigned()
    {
        var result = RunCli("example.com", "--type", "A");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Overall DNSSEC validation: Signed", result.StandardOutput);
    }

    [Fact]
    public void UnsignedDomain_WithRequireSigned_ExitsWithEight()
    {
        var result = RunCli("github.com", "--type", "A", "--require-signed", "--server", "1.1.1.1");

        Assert.Equal(8, result.ExitCode);
        Assert.Contains("Overall DNSSEC validation: Unsigned", result.StandardOutput);
    }

    [Fact]
    public void DohResolver_SignedDomain_ReturnsSigned()
    {
        var result = RunCli("example.com", "--type", "DS", "--server", "https://cloudflare-dns.com/dns-query");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("self-validating stub via https://cloudflare-dns.com/dns-query", result.StandardOutput);
        Assert.Contains("Overall DNSSEC validation: Signed", result.StandardOutput);
    }

    [Fact]
    public void QuietModeWithOutput_WritesFileOnly()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"dnssec-ut-{Guid.NewGuid():N}.log");
        try
        {
            var result = RunCli("example.com", "--type", "A", "--output", tempFile, "--quiet", "--server", "1.1.1.1");

            Assert.Equal(0, result.ExitCode);
            Assert.True(File.Exists(tempFile));
            string contents = File.ReadAllText(tempFile);
            Assert.Contains("example.com", contents);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public void QuietWithoutOutput_ReturnsSeven()
    {
        var result = RunCli("example.com", "--type", "A", "--quiet", "--server", "1.1.1.1");

        Assert.Equal(7, result.ExitCode);
        Assert.Contains("Quiet mode requires --output", result.StandardError);
    }

    [Fact]
    public void AppendWithoutOutput_ReturnsSix()
    {
        var result = RunCli("example.com", "--type", "A", "--append", "--server", "1.1.1.1");

        Assert.Equal(6, result.ExitCode);
        Assert.Contains("--append requires --output", result.StandardError);
    }

    [Fact]
    public void MultipleRecordTypes_ReturnsBoth()
    {
        var result = RunCli("example.com", "--type", "A,AAAA", "--server", "1.1.1.1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("-- A --", result.StandardOutput);
        Assert.Contains("-- AAAA --", result.StandardOutput);
    }

    [Fact]
    public void JsonOutput_Quiet_WritesJsonFile()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"dnssec-ut-{Guid.NewGuid():N}.json");
        try
        {
            var result = RunCli("example.com", "--type", "A", "--format", "json", "--output", tempFile, "--quiet", "--server", "1.1.1.1");

            Assert.Equal(0, result.ExitCode);
            Assert.True(File.Exists(tempFile));
            string contents = File.ReadAllText(tempFile);
            Assert.Contains("\"recordType\": \"A\"", contents);
            Assert.Contains("\"validationResult\": \"Signed\"", contents);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public void StubResolverMode_UsesExternalServer()
    {
        var result = RunCli("example.com", "--type", "A", "--server", "1.1.1.1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("self-validating stub via 1.1.1.1", result.StandardOutput);
    }

    [Fact]
    public void DomainKeyTxtRecord_IsReturned()
    {
        var result = RunCli("google._domainkey.vandenhooff.name", "--type", "TXT", "--server", "1.1.1.1");

        Assert.Equal(0, result.ExitCode);
        const string expectedSnippet = "v=DKIM1\\; k=rsa\\; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCl2Qrp5KF1uJnQSO0YuwInVPISQRrUciXtg/5hnQl6ed+UmYvWreLyuiyaiSd9X9Zu+aZQoeKm67HCxSMpC6G2ar0NludsXW69QdfzUpB5I6fzaLW8rl/RyeGkiQ3D66kvadK1wlNfUI7Dt9WtnUs8AFz/15xvODzgTMFJDiAcAwIDAQAB";
        Assert.Contains(expectedSnippet, result.StandardOutput);
    }

    private static CliResult RunCli(params string[] args)
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int exitCode = DnsSecCli.Run(args, stdout, stderr);
        return new CliResult(exitCode, stdout.ToString(), stderr.ToString());
    }

    private sealed record CliResult(int ExitCode, string StandardOutput, string StandardError);
}
