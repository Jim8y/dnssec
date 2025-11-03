using System.Diagnostics;
using System.Reflection;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using ARSoft.Tools.Net.Dns;

return DnsSecCli.Run(args, Console.Out, Console.Error);

public static class DnsSecCli
{
    private const int DefaultStubTimeoutMs = 10_000;
    private const int DefaultRecursiveTimeoutMs = 15_000;
    private static readonly string[] TxtSegmentPropertyCandidates = new[]
    {
        "TextDataArray",
        "TextDataList",
        "TextParts",
        "TextSegments"
    };

    public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length == 0 || args.Contains("--help", StringComparer.OrdinalIgnoreCase) || args.Contains("-h", StringComparer.OrdinalIgnoreCase))
        {
            CliOptions.PrintUsage(stdout);
            return args.Length == 0 ? 1 : 0;
        }

        if (!CliOptions.TryParse(args, out var options, out var errorMessage))
        {
            stderr.WriteLine($"Error: {errorMessage}");
            CliOptions.PrintUsage(stdout);
            return 1;
        }

        IDnsSecResolver resolver;
        if (options.DohServers.Count > 0)
        {
            int queryTimeout = options.TimeoutMs ?? DefaultStubTimeoutMs;
            resolver = new SelfValidatingInternalDnsSecStubResolver(options.DohServers[0], queryTimeout);
        }
        else if (options.Servers.Count > 0)
        {
            int queryTimeout = options.TimeoutMs ?? DefaultStubTimeoutMs;
            resolver = new SelfValidatingInternalDnsSecStubResolver(options.Servers, queryTimeout);
        }
        else
        {
            var recursiveResolver = new DnsSecRecursiveDnsResolver(new StaticResolverHintStore());
            recursiveResolver.QueryTimeout = options.TimeoutMs ?? DefaultRecursiveTimeoutMs;
            resolver = recursiveResolver;
        }

        try
        {
            var outcomes = new List<QueryOutcome>(options.RecordTypes.Count);
            var stopwatch = Stopwatch.StartNew();
            foreach (var recordType in options.RecordTypes)
            {
                var outcome = ResolveRecord(resolver, options.Domain, recordType, options.RecordClass);
                outcomes.Add(outcome);

                if (options.OverallTimeoutMs is int overallTimeout && stopwatch.ElapsedMilliseconds > overallTimeout)
                {
                    stderr.WriteLine("Query exceeded the overall timeout.");
                    return 4;
                }
            }

            var aggregateResult = AggregateValidation(outcomes);

            var dkimInfo = options.IsDkimLookup ? TryExtractDkimInfo(options, outcomes) : null;
            if (options.IsDkimLookup && dkimInfo != null)
            {
                if (dkimInfo.TxtSegments.Count == 0)
                {
                    stderr.WriteLine("No TXT records found for the DKIM selector.");
                }
                else if (string.IsNullOrWhiteSpace(dkimInfo.PublicKeyBase64))
                {
                    stderr.WriteLine("TXT record did not contain a DKIM p= public key value.");
                }
            }

            var rendered = RenderResults(options, outcomes, dkimInfo);
            if (options.AppendOutput && string.IsNullOrWhiteSpace(options.OutputPath))
            {
                stderr.WriteLine("--append requires --output to be specified.");
                return 6;
            }

            if (!options.Quiet)
            {
                WriteWithTrailingNewline(stdout, rendered);
            }
            else if (string.IsNullOrWhiteSpace(options.OutputPath))
            {
                stderr.WriteLine("Quiet mode requires --output to capture results.");
                return 7;
            }

            if (!string.IsNullOrWhiteSpace(options.OutputPath))
            {
                try
                {
                    var normalized = rendered.EndsWith(Environment.NewLine, StringComparison.Ordinal)
                        ? rendered
                        : rendered + Environment.NewLine;

                    if (options.AppendOutput)
                    {
                        File.AppendAllText(options.OutputPath, normalized);
                    }
                    else
                    {
                        File.WriteAllText(options.OutputPath, normalized);
                    }
                }
                catch (Exception ex)
                {
                    stderr.WriteLine($"Failed to write output file '{options.OutputPath}': {ex.Message}");
                    return 5;
                }
            }

            if (options.RequireSigned && aggregateResult != DnsSecValidationResult.Signed)
            {
                stderr.WriteLine($"DNSSEC signatures required (--require-signed); overall validation result was {aggregateResult}.");
                return aggregateResult == DnsSecValidationResult.Unsigned ? 8 : 2;
            }

            return aggregateResult switch
            {
                DnsSecValidationResult.Signed => 0,
                DnsSecValidationResult.Unsigned => 0,
                _ => 2
            };
        }
        catch (DnsSecValidationException ex)
        {
            stderr.WriteLine($"DNSSEC validation failed: {ex.Message}");
            WriteValidationFailureHint(stderr, options);
            return 2;
        }
        catch (Exception ex)
        {
            stderr.WriteLine($"Unexpected error: {ex.Message}");
            return 99;
        }
    }

    private static void WriteWithTrailingNewline(TextWriter output, string content)
    {
        if (string.IsNullOrEmpty(content))
        {
            output.WriteLine();
        }
        else
        {
            output.WriteLine(content);
        }
    }

    private static string RenderResults(CliOptions options, IReadOnlyList<QueryOutcome> outcomes, DkimLookupSummary? dkimInfo) =>
    options.Format == OutputFormat.Json
        ? RenderJsonResults(options, outcomes, dkimInfo)
        : RenderTextResults(options, outcomes, dkimInfo);

    private static string RenderTextResults(CliOptions options, IReadOnlyList<QueryOutcome> outcomes, DkimLookupSummary? dkimInfo)
{
    var sb = new StringBuilder();
    var recordClass = FormatRecordClass(options.RecordClass);
    sb.AppendLine($"Query: {options.Domain} {recordClass}");
    sb.AppendLine($"Requested types: {string.Join(", ", outcomes.Select(o => FormatRecordType(o.RecordType)).Distinct())}");
    if (options.DohServers.Count > 0)
    {
        sb.AppendLine($"Resolver: self-validating stub via {options.DohServers[0]} (DNS-over-HTTPS; timeout: {DescribeTimeout(options.TimeoutMs ?? DefaultStubTimeoutMs)})");
    }
    else if (options.Servers.Count > 0)
    {
        var list = string.Join(", ", options.Servers.Select(s => s.ToString()));
        sb.AppendLine($"Resolver: self-validating stub via {list} (timeout: {DescribeTimeout(options.TimeoutMs ?? DefaultStubTimeoutMs)})");
    }
    else
    {
        sb.AppendLine($"Resolver: built-in recursive resolver with root trust anchors (timeout: {DescribeTimeout(options.TimeoutMs ?? DefaultRecursiveTimeoutMs)})");
    }

    if (options.OverallTimeoutMs is int overall)
    {
        sb.AppendLine($"Overall timeout: {DescribeTimeout(overall)}");
    }

    var aggregate = AggregateValidation(outcomes);
    sb.AppendLine($"Overall DNSSEC validation: {aggregate}");
    sb.AppendLine(DescribeValidation(aggregate));

    foreach (var outcome in outcomes)
    {
        sb.AppendLine();
        sb.AppendLine($"-- {FormatRecordType(outcome.RecordType)} --");
        sb.AppendLine($"Validation result: {outcome.Result.ValidationResult}");
        sb.AppendLine(DescribeValidation(outcome.Result.ValidationResult));

        if (outcome.Result.Records.Count == 0)
        {
            sb.AppendLine("No records found for this type.");
            continue;
        }

        sb.AppendLine("Records:");
        foreach (var record in outcome.Result.Records)
        {
            sb.AppendLine($"  {record}");
        }
    }

    if (options.IsDkimLookup)
    {
        sb.AppendLine();
        sb.AppendLine("DKIM lookup:");
        sb.AppendLine($"  Selector: {options.DkimSelector}");
        sb.AppendLine($"  Domain  : {options.DkimDomain}");
        sb.AppendLine($"  Record  : {options.Domain}");
        if (dkimInfo != null && dkimInfo.TxtSegments.Count > 0)
        {
            sb.AppendLine("  TXT data:");
            foreach (var segment in dkimInfo.TxtSegments)
            {
                sb.AppendLine($"    {segment}");
            }
        }
        else
        {
            sb.AppendLine("  TXT data: <none>");
        }
        sb.AppendLine($"  Public key (base64): {dkimInfo?.PublicKeyBase64 ?? "<not found>"}");
    }

    return sb.ToString();
}

    private static string RenderJsonResults(CliOptions options, IReadOnlyList<QueryOutcome> outcomes, DkimLookupSummary? dkimInfo)
{
    var aggregate = AggregateValidation(outcomes);
    var resolverMode = options.DohServers.Count > 0
        ? "stub-doh"
        : options.Servers.Count > 0
            ? "stub"
            : "recursive";
    var resolverServers = options.DohServers.Count > 0
        ? options.DohServers.Select(u => u.ToString()).ToArray()
        : options.Servers.Select(s => s.ToString()).ToArray();
    var resolverTransport = options.DohServers.Count > 0
        ? "https"
        : options.Servers.Count > 0
            ? "udp/tcp"
            : "recursive";
    var payload = new
    {
        query = new
        {
            domain = options.Domain,
            recordClass = FormatRecordClass(options.RecordClass),
            recordTypes = outcomes.Select(o => FormatRecordType(o.RecordType)).ToArray()
        },
        resolver = new
        {
            mode = resolverMode,
            transport = resolverTransport,
            servers = resolverServers,
            timeoutMs = options.TimeoutMs ?? (options.HasStubResolver ? DefaultStubTimeoutMs : DefaultRecursiveTimeoutMs),
            overallTimeoutMs = options.OverallTimeoutMs
        },
        dnssec = new
        {
            overallResult = aggregate.ToString(),
            description = DescribeValidation(aggregate)
        },
        responses = outcomes.Select(o => new
        {
            recordType = FormatRecordType(o.RecordType),
            validationResult = o.Result.ValidationResult.ToString(),
            description = DescribeValidation(o.Result.ValidationResult),
            records = o.Result.Records.Select(CreateRecordDto).ToArray()
        }).ToArray(),
        dkim = options.IsDkimLookup ? new
        {
            selector = options.DkimSelector,
            domain = options.DkimDomain,
            recordName = options.Domain,
            txtSegments = dkimInfo?.TxtSegments ?? Array.Empty<string>(),
            publicKeyBase64 = dkimInfo?.PublicKeyBase64
        } : null
    };

    return JsonSerializer.Serialize(payload, new JsonSerializerOptions
    {
        WriteIndented = true
    });
}

    private static object CreateRecordDto(DnsRecordBase record)
{
    return new
    {
        name = record.Name.ToString(),
        recordType = FormatRecordType(record.RecordType),
        recordClass = FormatRecordClass(record.RecordClass),
        timeToLive = record.TimeToLive,
        data = CreateRecordData(record)
    };
}

    private static object CreateRecordData(DnsRecordBase record) =>
    record switch
    {
        ARecord a => new { address = a.Address.ToString() },
        AaaaRecord aaaa => new { address = aaaa.Address.ToString() },
        CNameRecord cname => new { target = cname.CanonicalName.ToString() },
        NsRecord ns => new { target = ns.NameServer.ToString() },
        PtrRecord ptr => new { target = ptr.PointerDomainName.ToString() },
        TxtRecord txt => new { text = txt.TextData },
        MxRecord mx => new { preference = mx.Preference, exchange = mx.ExchangeDomainName.ToString() },
        SoaRecord soa => new
        {
            primaryNameServer = soa.MasterName.ToString(),
            responsibleMailbox = soa.ResponsibleName.ToString(),
            serial = soa.SerialNumber,
            refresh = soa.RefreshInterval,
            retry = soa.RetryInterval,
            expire = soa.ExpireInterval,
            negativeCachingTtl = soa.NegativeCachingTTL
        },
        SrvRecord srv => new { priority = srv.Priority, weight = srv.Weight, port = srv.Port, target = srv.Target.ToString() },
        CAARecord caa => new { flags = caa.Flags, tag = caa.Tag, value = caa.Value },
        DsRecord ds => new
        {
            keyTag = ds.KeyTag,
            algorithm = ds.Algorithm.ToString(),
            digestType = ds.DigestType.ToString(),
            digestHex = Convert.ToHexString(ds.Digest),
            digestBase64 = Convert.ToBase64String(ds.Digest)
        },
        DnsKeyRecord key => new
        {
            flags = key.Flags,
            protocol = key.Protocol,
            algorithm = key.Algorithm.ToString(),
            publicKeyBase64 = Convert.ToBase64String(key.PublicKey)
        },
        RrSigRecord sig => new
        {
            typeCovered = sig.TypeCovered.ToString(),
            algorithm = sig.Algorithm.ToString(),
            labels = sig.Labels,
            originalTtl = sig.OriginalTimeToLive,
            signatureExpiration = sig.SignatureExpiration,
            signatureInception = sig.SignatureInception,
            keyTag = sig.KeyTag,
            signersName = sig.SignersName.ToString(),
            signatureBase64 = Convert.ToBase64String(sig.Signature)
        },
        _ => new { text = record.ToString() }
    };

    private static DkimLookupSummary? TryExtractDkimInfo(CliOptions options, IReadOnlyList<QueryOutcome> outcomes)
{
    if (!options.IsDkimLookup)
    {
        return null;
    }

    string selector = options.DkimSelector ?? string.Empty;
    string domain = options.DkimDomain ?? string.Empty;
    string recordName = options.Domain;

    var txtRecords = outcomes
        .SelectMany(o => o.Result.Records.OfType<TxtRecord>())
        .ToList();

    if (txtRecords.Count == 0)
    {
        return new DkimLookupSummary(selector, domain, recordName, Array.Empty<string>(), null);
    }

    foreach (var txt in txtRecords)
    {
        var segments = GetTxtSegments(txt);
        var publicKey = ExtractDkimPublicKey(segments);
        if (!string.IsNullOrWhiteSpace(publicKey))
        {
            return new DkimLookupSummary(selector, domain, recordName, segments, publicKey);
        }
    }

    var fallbackSegments = GetTxtSegments(txtRecords[0]);
    return new DkimLookupSummary(selector, domain, recordName, fallbackSegments, null);
}

    private static IReadOnlyList<string> GetTxtSegments(TxtRecord record)
{
    foreach (var propertyName in TxtSegmentPropertyCandidates)
    {
        var property = record.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (property?.GetValue(record) is IEnumerable<string> enumerable)
        {
            var segments = enumerable.Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .ToArray();
            if (segments.Length > 0)
            {
                return segments;
            }
        }
    }

    if (!string.IsNullOrEmpty(record.TextData))
    {
        return new[] { record.TextData };
    }

    var fallback = record.ToString();
    return string.IsNullOrEmpty(fallback) ? Array.Empty<string>() : new[] { fallback };
}

    private static string? ExtractDkimPublicKey(IReadOnlyList<string> segments)
{
    if (segments.Count == 0)
    {
        return null;
    }

    var combined = string.Concat(segments).Replace("\"", string.Empty);
    foreach (var part in combined.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (part.StartsWith("p=", StringComparison.OrdinalIgnoreCase))
        {
            var value = part[2..].Trim();
            return value.Length > 0 ? value : null;
        }
    }

    return null;
}

    private static QueryOutcome ResolveRecord(IDnsSecResolver resolver, string domain, RecordType recordType, RecordClass recordClass)
{
    var result = resolver.ResolveSecure<DnsRecordBase>(domain, recordType, recordClass);
    return new QueryOutcome(recordType, result);
}

    private static DnsSecValidationResult AggregateValidation(IEnumerable<QueryOutcome> outcomes)
{
    bool sawUnsigned = false;
    bool any = false;

    foreach (var outcome in outcomes)
    {
        any = true;
        switch (outcome.Result.ValidationResult)
        {
            case DnsSecValidationResult.Bogus:
                return DnsSecValidationResult.Bogus;
            case DnsSecValidationResult.Indeterminate:
                return DnsSecValidationResult.Indeterminate;
            case DnsSecValidationResult.Unsigned:
                sawUnsigned = true;
                break;
        }
    }

    if (!any)
    {
        return DnsSecValidationResult.Indeterminate;
    }

    return sawUnsigned ? DnsSecValidationResult.Unsigned : DnsSecValidationResult.Signed;
}

    private static void WriteValidationFailureHint(TextWriter stderr, CliOptions options)
    {
        if (options.DohServers.Count > 0)
        {
            return;
        }

        if (options.Servers.Count > 0)
        {
            stderr.WriteLine("Hint: Upstream resolvers sometimes strip DNSSEC data. If that persists, try a DNS-over-HTTPS endpoint, e.g. --server https://cloudflare-dns.com/dns-query");
        }
        else
        {
            stderr.WriteLine("Hint: Some networks block DNSSEC. Re-run with a DNS-over-HTTPS resolver, e.g. --server https://cloudflare-dns.com/dns-query");
        }
    }

    private static string DescribeTimeout(int? timeoutMs)
{
    return timeoutMs is int ms ? $"{ms} ms" : "library default";
}

    private static string DescribeValidation(DnsSecValidationResult validation)
{
    return validation switch
    {
        DnsSecValidationResult.Signed => "All responses validated successfully with DNSSEC signatures.",
        DnsSecValidationResult.Unsigned => "Zone is unsigned, but proof of non-existence (opt-out) validates the response.",
        DnsSecValidationResult.Bogus => "Signatures failed to validate. Treat the response as untrustworthy.",
        _ => "Unable to determine DNSSEC status. Response should not be trusted without additional checks."
    };
}

    private static string FormatRecordClass(RecordClass recordClass) =>
    recordClass switch
    {
        RecordClass.INet => "IN",
        RecordClass.Chaos => "CH",
        RecordClass.Hesiod => "HS",
        _ => recordClass.ToString()
    };

    private static string FormatRecordType(RecordType recordType) => recordType.ToString().ToUpperInvariant();
}

internal sealed record QueryOutcome(RecordType RecordType, DnsSecResult<DnsRecordBase> Result);
internal sealed record DkimLookupSummary(string Selector, string Domain, string RecordName, IReadOnlyList<string> TxtSegments, string? PublicKeyBase64);

internal sealed class CliOptions
{
    public string Domain { get; private set; } = string.Empty;
    public RecordClass RecordClass { get; private set; } = RecordClass.INet;
    public List<IPAddress> Servers { get; } = new();
    public List<Uri> DohServers { get; } = new();
    public bool HasStubResolver => Servers.Count > 0 || DohServers.Count > 0;
    public string? DkimSelector { get; private set; }
    public string? DkimDomain { get; private set; }
    public bool IsDkimLookup => !string.IsNullOrWhiteSpace(DkimSelector) && !string.IsNullOrWhiteSpace(DkimDomain);
    public int? TimeoutMs { get; private set; }
    public int? OverallTimeoutMs { get; private set; }
    public OutputFormat Format { get; private set; } = OutputFormat.Text;
    public string? OutputPath { get; private set; }
    public bool AppendOutput { get; private set; }
    public bool Quiet { get; private set; }
    public bool RequireSigned { get; private set; }
    public List<RecordType> RecordTypes { get; } = new();

    public static bool TryParse(string[] args, out CliOptions options, out string? error)
    {
        options = new CliOptions();
        error = null;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg.StartsWith("-", StringComparison.Ordinal))
            {
                string lowered = arg.ToLowerInvariant();

                if (lowered is "--quiet" or "-q")
                {
                    options.Quiet = true;
                    continue;
                }

                if (lowered == "--append")
                {
                    options.AppendOutput = true;
                    continue;
                }

                if (lowered == "--require-signed")
                {
                    options.RequireSigned = true;
                    continue;
                }

                if (!TryReadOptionValue(args, ref i, out string value, out error))
                {
                    return false;
                }

                switch (lowered)
                {
                    case "--type":
                    case "--record-type":
                    case "-t":
                        int recordTypeCount = options.RecordTypes.Count;
                        foreach (string entry in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            if (!Enum.TryParse(entry, true, out RecordType parsedType))
                            {
                                error = $"Unknown record type '{entry}'.";
                                return false;
                            }
                            options.RecordTypes.Add(parsedType);
                        }

                        if (options.RecordTypes.Count == recordTypeCount)
                        {
                            error = "At least one record type must be provided after --type.";
                            return false;
                        }
                        break;

                    case "--class":
                    case "-c":
                        if (!TryParseRecordClass(value, out var recordClass))
                        {
                            error = $"Unknown record class '{value}'.";
                            return false;
                        }
                        options.RecordClass = recordClass;
                        break;

                    case "--dkim-selector":
                        if (string.IsNullOrWhiteSpace(value))
                        {
                            error = "--dkim-selector requires a selector value.";
                            return false;
                        }
                        options.DkimSelector = value.Trim().TrimEnd('.');
                        break;

                    case "--dkim-domain":
                        if (string.IsNullOrWhiteSpace(value))
                        {
                            error = "--dkim-domain requires a domain value.";
                            return false;
                        }
                        options.DkimDomain = value.Trim().TrimEnd('.');
                        break;

                    case "--server":
                    case "--resolver":
                    case "-s":
                        int resolverCountBefore = options.Servers.Count + options.DohServers.Count;
                        foreach (string entry in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            if (IPAddress.TryParse(entry, out var address))
                            {
                                if (options.DohServers.Count > 0)
                                {
                                    error = "Cannot mix IP servers with DNS-over-HTTPS endpoints in --server.";
                                    return false;
                                }
                                options.Servers.Add(address);
                                continue;
                            }

                            if (Uri.TryCreate(entry, UriKind.Absolute, out var uri) && uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                            {
                                if (options.Servers.Count > 0)
                                {
                                    error = "Cannot mix DNS-over-HTTPS endpoints with IP servers in --server.";
                                    return false;
                                }

                                if (options.DohServers.Count > 0)
                                {
                                    error = "Only one DNS-over-HTTPS endpoint is supported with --server.";
                                    return false;
                                }

                                options.DohServers.Add(uri);
                                continue;
                            }

                            error = $"Invalid server value '{entry}'. Provide an IP address or an https:// DNS-over-HTTPS endpoint.";
                            return false;
                        }

                        if (options.Servers.Count + options.DohServers.Count == resolverCountBefore)
                        {
                            error = "At least one server endpoint must be provided after --server.";
                            return false;
                        }
                        break;

                    case "--timeout":
                        if (!int.TryParse(value, out int timeout) || timeout <= 0)
                        {
                            error = $"Invalid timeout '{value}'. Timeout must be a positive integer (milliseconds).";
                            return false;
                        }
                        options.TimeoutMs = timeout;
                        break;

                    case "--overall-timeout":
                        if (!int.TryParse(value, out int overallTimeout) || overallTimeout <= 0)
                        {
                            error = $"Invalid overall timeout '{value}'. Timeout must be a positive integer (milliseconds).";
                            return false;
                        }
                        options.OverallTimeoutMs = overallTimeout;
                        break;

                    case "--format":
                    case "-f":
                        if (!TryParseFormat(value, out var format))
                        {
                            error = $"Unknown output format '{value}'. Use 'text' or 'json'.";
                            return false;
                        }
                        options.Format = format;
                        break;

                    case "--output":
                    case "-o":
                        if (string.IsNullOrWhiteSpace(value))
                        {
                            error = "--output requires a file path.";
                            return false;
                        }
                        options.OutputPath = value;
                        break;

                    default:
                        error = $"Unknown option '{arg}'.";
                        return false;
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(options.Domain))
                {
                    error = $"Unexpected argument '{arg}'. Only one domain name should be provided.";
                    return false;
                }

                options.Domain = arg.Trim();
            }
        }

        if (options.DkimSelector is null ^ options.DkimDomain is null)
        {
            error = "--dkim-selector and --dkim-domain must be provided together.";
            return false;
        }

        if (options.IsDkimLookup)
        {
            string derivedRecord = $"{options.DkimSelector}._domainkey.{options.DkimDomain}".Trim('.');
            string normalizedDerived = derivedRecord.ToLowerInvariant();
            if (string.IsNullOrEmpty(options.Domain))
            {
                options.Domain = normalizedDerived;
            }
            else
            {
                string normalizedDomain = options.Domain.TrimEnd('.').ToLowerInvariant();
                if (!normalizedDomain.Equals(normalizedDerived, StringComparison.Ordinal))
                {
                    error = $"Domain argument '{options.Domain}' does not match DKIM selector/domain '{derivedRecord}'.";
                    return false;
                }

                options.Domain = normalizedDomain;
            }

            if (options.RecordTypes.Count == 0)
            {
                options.RecordTypes.Add(RecordType.Txt);
            }
            else if (!options.RecordTypes.Contains(RecordType.Txt))
            {
                error = "DKIM lookups require TXT records. Include TXT in --type.";
                return false;
            }
        }
        else
        {
            if (string.IsNullOrEmpty(options.Domain))
            {
                error = "A domain name must be provided.";
                return false;
            }

            options.Domain = options.Domain.Trim().TrimEnd('.');
            if (string.IsNullOrEmpty(options.Domain))
            {
                error = "A domain name must be provided.";
                return false;
            }

            if (options.RecordTypes.Count == 0)
            {
                options.RecordTypes.Add(RecordType.A);
            }
        }

        return true;
    }

    public static void PrintUsage(TextWriter output)
    {
        output.WriteLine("Usage: dnssec <domain> [options]");
        output.WriteLine();
        output.WriteLine("Options:");
        output.WriteLine("  --type, -t <TYPE>        DNS record type(s) to query (default: A). Accepts comma-separated values.");
        output.WriteLine("  --class, -c <CLASS>      DNS record class (default: IN / INet).");
        output.WriteLine("  --server, -s <ENDPOINT>[,ENDPOINT]");
        output.WriteLine("                          Upstream validating resolver(s) to query. Accepts IP addresses or https:// DNS-over-HTTPS endpoints.");
        output.WriteLine("      --dkim-selector <NAME>");
        output.WriteLine("                          DKIM selector to query (requires --dkim-domain).");
        output.WriteLine("      --dkim-domain <DOMAIN>");
        output.WriteLine("                          DKIM base domain. Record queried is <selector>._domainkey.<domain>.");
        output.WriteLine("  --format, -f <FORMAT>    Output format: text (default) or json.");
        output.WriteLine("  --output, -o <PATH>      Write the rendered output to the specified file.");
        output.WriteLine("      --append             Append to the output file instead of overwriting.");
        output.WriteLine("  --quiet, -q              Suppress stdout output (errors still print).");
        output.WriteLine("      --require-signed     Treat unsigned DNS responses as failures (non-zero exit).");
        output.WriteLine("  --timeout <MS>           Query timeout in milliseconds.");
        output.WriteLine("  --overall-timeout <MS>   Cancel the entire run if it exceeds this duration (milliseconds).");
        output.WriteLine("  --help, -h               Show this help message.");
        output.WriteLine();
        output.WriteLine("Without --server, the tool performs full recursion with built-in root hints and");
        output.WriteLine("trust anchors to validate DNSSEC signatures end-to-end.");
    }

    private static bool TryReadOptionValue(string[] args, ref int index, out string value, out string? error)
    {
        if (index + 1 >= args.Length)
        {
            error = $"Option '{args[index]}' expects a value.";
            value = string.Empty;
            return false;
        }

        index++;
        value = args[index];
        error = null;
        return true;
    }

    private static bool TryParseFormat(string input, out OutputFormat format)
    {
        if (input.Equals("text", StringComparison.OrdinalIgnoreCase))
        {
            format = OutputFormat.Text;
            return true;
        }

        if (input.Equals("json", StringComparison.OrdinalIgnoreCase))
        {
            format = OutputFormat.Json;
            return true;
        }

        format = default;
        return false;
    }

    private static bool TryParseRecordClass(string input, out RecordClass recordClass)
    {
        if (Enum.TryParse<RecordClass>(input, true, out recordClass))
        {
            return true;
        }

        if (input.Equals("IN", StringComparison.OrdinalIgnoreCase))
        {
            recordClass = RecordClass.INet;
            return true;
        }

        if (input.Equals("CH", StringComparison.OrdinalIgnoreCase))
        {
            recordClass = RecordClass.Chaos;
            return true;
        }

        if (input.Equals("HS", StringComparison.OrdinalIgnoreCase))
        {
            recordClass = RecordClass.Hesiod;
            return true;
        }

        recordClass = default;
        return false;
    }
}

internal enum OutputFormat
{
    Text,
    Json
}
