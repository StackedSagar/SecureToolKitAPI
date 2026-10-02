using System.Security.Cryptography;
using Azure.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;
using SecureToolKitAPI.Cryptography.KeyGeneration;
using SecureToolKitAPI.Cryptography.Signing;
using SecureToolKitAPI.ExceptionHandling;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit;

public class CryptographyHelpersTests
{
    [Fact]
    public void Base64Text_round_trips_utf8_and_validates_bad_inputs()
    {
        var payload = new byte[] { 0x00, 0x01, 0x7F, 0x80, 0xFF };
        var encoded = Base64Text.Encode(payload);

        Assert.Equal(payload, Base64Text.Decode(encoded, "payload"));
        Assert.True(Base64Text.TryDecode(encoded, out var roundTrip));
        Assert.Equal(payload, roundTrip);
        Assert.False(Base64Text.TryDecode("not-base64!", out _));

        var message = "hello, world";
        Assert.Equal(message, Base64Text.FromUtf8(Base64Text.ToUtf8(message)));

        Assert.Contains("required", Assert.Throws<CryptographicRequestException>(() => Base64Text.Decode(string.Empty, "key")).Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not valid Base64", Assert.Throws<CryptographicRequestException>(() => Base64Text.Decode("not-base64!", "key")).Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("valid UTF-8", Assert.Throws<CryptographicRequestException>(() => Base64Text.FromUtf8(new byte[] { 0xFF, 0xFF })).Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(256, "nistP256")]
    [InlineData(384, "nistP384")]
    [InlineData(521, "nistP521")]
    public void EcCurves_support_the_documented_key_sizes(int keySizeBits, string curveName)
    {
        var curve = EcCurves.FromKeySize(keySizeBits);
        Assert.Equal(curveName, curve.Oid.FriendlyName);
    }

    [Fact]
    public void EcCurves_reject_unsupported_key_sizes()
    {
        var exception = Assert.Throws<CryptographicRequestException>(() => EcCurves.FromKeySize(1024));
        Assert.Contains("Unsupported elliptic curve size 1024", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SecretText_helpers_expose_documented_alphabets_and_sampling_logic()
    {
        Assert.Equal(62, SecretText.Base62.Length);
        Assert.Equal(64, SecretText.Base64UrlAlphabet.Length);
        Assert.Equal(SecretText.HexLower, SecretText.Alphabet(RandomStringAlphabet.Hex));
        Assert.Equal(SecretText.HexUpper, SecretText.Alphabet(RandomStringAlphabet.HexUpper));
        Assert.Equal("digits and letters", SecretText.Describe(RandomStringAlphabet.Alphanumeric));
        Assert.Equal("digits (10 character alphabet)", SecretText.Describe(BackupCodeFormat.Numeric));
        Assert.True(SecretText.CharactersFor(16, 62) > 0);

        var sample = SecretText.Sample("ABCDEF", 12);
        Assert.Equal(12, sample.Length);
        Assert.All(sample, character => Assert.Contains(character, "ABCDEF"));

        var material = SecretText.Material(4, SecretEncoding.Base62);
        Assert.True(material.EntropyBits > 0d);
        Assert.NotEmpty(material.Value);
    }

    [Fact]
    public void KeyGeneratorBase_validates_size_before_generating_and_uses_the_default_when_omitted()
    {
        var generator = new TestKeyGenerator();

        var defaultGenerated = generator.Generate(null);
        var explicitGenerated = generator.Generate(128);

        Assert.Equal(256, defaultGenerated.KeySizeBits);
        Assert.Equal(128, explicitGenerated.KeySizeBits);
        Assert.Equal("test", defaultGenerated.Algorithm);

        var exception = Assert.Throws<CryptographicRequestException>(() => generator.Generate(4096));
        Assert.Contains("Invalid key size 4096", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GlobalExceptionHandler_writes_400_problem_details_for_cryptographic_errors_and_500_for_unexpected_errors()
    {
        var problemDetailsService = new FakeProblemDetailsService();
        var handler = new GlobalExceptionHandler(problemDetailsService, NullLogger<GlobalExceptionHandler>.Instance);

        var badRequestContext = new DefaultHttpContext();
        badRequestContext.Request.Method = HttpMethods.Post;
        badRequestContext.Request.Path = "/api/demo";

        var badRequestHandled = await handler.TryHandleAsync(
            badRequestContext,
            new CryptographicRequestException("The key is invalid."),
            CancellationToken.None);

        Assert.True(badRequestHandled);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequestContext.Response.StatusCode);
        Assert.Equal("Invalid cryptographic request.", problemDetailsService.LastProblemDetails?.Title);
        Assert.Equal("The key is invalid.", problemDetailsService.LastProblemDetails?.Detail);

        var unexpectedContext = new DefaultHttpContext();
        unexpectedContext.Request.Method = HttpMethods.Get;
        unexpectedContext.Request.Path = "/api/unexpected";

        var unexpectedHandled = await handler.TryHandleAsync(
            unexpectedContext,
            new InvalidOperationException("Boom"),
            CancellationToken.None);

        Assert.True(unexpectedHandled);
        Assert.Equal(StatusCodes.Status500InternalServerError, unexpectedContext.Response.StatusCode);
        Assert.Equal("An unexpected error occurred.", problemDetailsService.LastProblemDetails?.Title);
        Assert.Null(problemDetailsService.LastProblemDetails?.Detail);
    }

    [Fact]
    public void OptionName_parse_handles_compact_names_and_invalid_values_consistently()
    {
        Assert.Equal(SecretEncoding.Base64Url, DeveloperSecretOptions.ParseEncoding("base64 url"));
        Assert.Equal(SecretEncoding.Hex, DeveloperSecretOptions.ParseEncoding("HEX"));
        Assert.Equal(JwtAlgorithm.HS256, DeveloperSecretOptions.ParseJwtAlgorithm("hs-256"));
        Assert.Equal(OAuthTokenKind.RefreshToken, DeveloperSecretOptions.ParseOAuthTokenKind("refresh_token"));
        Assert.Equal(RandomStringAlphabet.Base64Url, DeveloperSecretOptions.ParseAlphabet("base64-url"));

        var invalidEncoding = Assert.Throws<CryptographicRequestException>(() => DeveloperSecretOptions.ParseEncoding("nope"));
        Assert.Contains("Supported values", invalidEncoding.Message, StringComparison.Ordinal);

        var invalidAlgorithm = Assert.Throws<CryptographicRequestException>(() => DeveloperSecretOptions.ParseJwtAlgorithm("123"));
        Assert.Contains("Unsupported JWT algorithm", invalidAlgorithm.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PasswordCharsets_cover_single_set_exclusion_and_invalid_set_errors()
    {
        Assert.Equal("34679", PasswordCharsets.Set(PasswordCharacters.Digits, excludeAmbiguous: true));
        Assert.NotEmpty(PasswordCharsets.For(PasswordCharacters.Symbols, excludeAmbiguous: false));

        var invalidSet = Assert.Throws<ArgumentOutOfRangeException>(() => PasswordCharsets.Set((PasswordCharacters)999, excludeAmbiguous: false));
        Assert.Contains("single character set", invalidSet.Message, StringComparison.Ordinal);

        var invalidSelection = Assert.Throws<CryptographicRequestException>(() => PasswordCharsets.For(PasswordCharacters.None, excludeAmbiguous: true));
        Assert.Contains("At least one character set", invalidSelection.Message, StringComparison.Ordinal);
        Assert.Equal("digits (10 character alphabet)", PasswordCharsets.Describe(PasswordCharacters.Digits, excludeAmbiguous: false));
    }

    [Fact]
    public void SecretText_covers_invalid_named_alphabets_and_sampling_paths()
    {
        Assert.Equal("sampled from 62 digits and letters", SecretText.Describe(SecretEncoding.Base62));
        Assert.Equal("the URL-safe Base64 alphabet", SecretText.Describe(RandomStringAlphabet.Base64Url));
        Assert.Equal("a supplied alphabet", SecretText.Describe((RandomStringAlphabet)99));

        var alphabet = SecretText.Alphabet(RandomStringAlphabet.HexUpper);
        Assert.Equal(SecretText.HexUpper, alphabet);

        var sample = SecretText.Sample("ABCDEF", 12);
        Assert.Equal(12, sample.Length);
        Assert.All(sample, character => Assert.Contains(character, "ABCDEF"));

        var material = SecretText.Material(4, SecretEncoding.Base62);
        Assert.NotEmpty(material.Value);
        Assert.True(material.EntropyBits > 0d);

        Assert.Throws<ArgumentOutOfRangeException>(() => SecretText.Alphabet((RandomStringAlphabet)101));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecretText.Alphabet((BackupCodeFormat)101));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecretText.Encode(4, (SecretEncoding)999));
    }

    [Fact]
    public void SshWireFormat_covers_zero_mpint_and_missing_component_errors()
    {
        var rsaKey = SshWireFormat.RsaPublicKeyBlob(new RSAParameters
        {
            Exponent = [1, 0, 1],
            Modulus = [0]
        });

        Assert.NotEmpty(rsaKey);
        Assert.Equal("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAAA==", SshWireFormat.AuthorizedKeysLine(SshWireFormat.RsaKeyType, rsaKey, null));

        var authorized = SshWireFormat.AuthorizedKeysLine("ssh-rsa", new byte[] { 0x01, 0x02, 0x03 }, "demo");
        Assert.Contains(" demo", authorized, StringComparison.Ordinal);

        var missing = Assert.Throws<InvalidOperationException>(() => SshWireFormat.EcdsaPublicKeyBlob(
            "nistp256",
            new ECPoint { X = null, Y = [0x01, 0x02] }));

        Assert.Contains("public point", missing.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EcdsaSignatureMethod_covers_invalid_key_and_signature_failures()
    {
        var method = new EcdsaSignatureMethod();

        var rsaPrivateKey = Convert.ToBase64String(RSA.Create(2048).ExportRSAPrivateKey());
        var signFailure = Assert.Throws<CryptographicRequestException>(() => method.Sign(rsaPrivateKey, "hello"));
        Assert.Contains("valid ECDSA", signFailure.Message, StringComparison.Ordinal);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaPrivateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
        var ecdsaPublicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        var signature = method.Sign(ecdsaPrivateKey, "hello");

        var wrongTypeKey = Convert.ToBase64String(RSA.Create(2048).ExportRSAPublicKey());
        Assert.Throws<CryptographicRequestException>(() => method.Verify(wrongTypeKey, "hello", signature));

        Assert.False(method.Verify(ecdsaPublicKey, "hello", Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))));
    }

    //[Fact]
    //public void Program_decides_when_key_vault_should_be_used_without_touching_azure()
    //{
    //    var productionEnvironment = new FakeHostEnvironment("Production");
    //    var testingEnvironment = new FakeHostEnvironment("Testing");
    //    var productionBuilder = new ConfigurationBuilder();
    //    var testingBuilder = new ConfigurationBuilder();
    //    var productionConfigured = false;
    //    var testingConfigured = false;

    //    Assert.True(Program.ShouldUseKeyVault(productionEnvironment, "https://example.vault.azure.net"));
    //    Assert.False(Program.ShouldUseKeyVault(testingEnvironment, "https://example.vault.azure.net"));
    //    Assert.False(Program.ShouldUseKeyVault(productionEnvironment, string.Empty));

    //    Program.ConfigureKeyVault(
    //        productionBuilder,
    //        productionEnvironment,
    //        "https://example.vault.azure.net",
    //        new FakeTokenCredential(),
    //        (_, _, _) => productionConfigured = true);

    //    Program.ConfigureKeyVault(
    //        testingBuilder,
    //        testingEnvironment,
    //        "https://example.vault.azure.net",
    //        new FakeTokenCredential(),
    //        (_, _, _) => testingConfigured = true);

    //    Assert.True(productionConfigured);
    //    Assert.False(testingConfigured);
    //    Assert.Empty(testingBuilder.Sources);
    //}

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string ApplicationName { get; set; } = "SecureToolKitAPI";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public string EnvironmentName { get; set; } = environmentName;
    }

    private sealed class FakeTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("token", DateTimeOffset.UtcNow.AddMinutes(5));

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new AccessToken("token", DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    private sealed class TestKeyGenerator : KeyGeneratorBase
    {
        public override string Name => "test";

        public override string Description => "test generator";

        public override IReadOnlyCollection<int> SupportedKeySizes => [128, 256];

        public override int DefaultKeySize => 256;

        protected override GeneratedKey GenerateCore(int keySizeBits) => new()
        {
            Algorithm = Name,
            KeySizeBits = keySizeBits,
            Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            KeyFormat = "base64"
        };
    }

    private sealed class FakeProblemDetailsService : IProblemDetailsService
    {
        public ProblemDetails? LastProblemDetails { get; private set; }

        public ValueTask WriteAsync(ProblemDetailsContext context)
        {
            LastProblemDetails = context.ProblemDetails;
            context.HttpContext.Response.StatusCode = context.ProblemDetails.Status ?? StatusCodes.Status200OK;
            return ValueTask.CompletedTask;
        }

        public ValueTask<bool> TryWriteAsync(ProblemDetailsContext context)
        {
            LastProblemDetails = context.ProblemDetails;
            context.HttpContext.Response.StatusCode = context.ProblemDetails.Status ?? StatusCodes.Status200OK;
            return ValueTask.FromResult(true);
        }
    }
}
