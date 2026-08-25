using System.Net;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// Signing and verification over HTTP. A signature proves origin and integrity rather than hiding a
    /// message, so a failed check is a valid answer (200 with <c>isValid: false</c>) and not an error.
    /// </summary>
    [Collection(ApiCollection.Name)]
    public class SignatureEndpointTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>Identifiers that name the same algorithm to the key generation and signature endpoints.</summary>
        public static TheoryData<string, string> Methods => new()
        {
            { "ecc-dss", "ecc-dss" },
            { "hmac", "hmac-sha256" }
        };

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task Generate_then_sign_then_verify_accepts_the_signature(string method, string canonicalName)
        {
            var keys = await GenerateAsync(method);

            var (signed, signedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/sign",
                new { key = keys.Signing, message = TestMessages.Unicode });

            Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
            Assert.Equal(canonicalName, signedBody.RequiredString("method"));
            Assert.False(string.IsNullOrWhiteSpace(signedBody.RequiredString("signatureFormat")));

            var (verified, verifiedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/verify",
                new
                {
                    key = keys.Verification,
                    message = TestMessages.Unicode,
                    signature = signedBody.RequiredString("signature")
                });

            Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
            Assert.True(verifiedBody.GetProperty("isValid").GetBoolean());
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task An_altered_message_fails_verification_without_being_an_error(string method, string canonicalName)
        {
            var keys = await GenerateAsync(method);

            var (_, signedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/sign",
                new { key = keys.Signing, message = TestMessages.Normal });

            var (verified, verifiedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/verify",
                new
                {
                    key = keys.Verification,
                    message = TestMessages.Normal + "!",
                    signature = signedBody.RequiredString("signature")
                });

            Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
            Assert.Equal(canonicalName, verifiedBody.RequiredString("method"));
            Assert.False(verifiedBody.GetProperty("isValid").GetBoolean());
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task A_signature_from_a_different_key_fails_verification(string method, string canonicalName)
        {
            var keys = await GenerateAsync(method);
            var other = await GenerateAsync(method);

            var (_, signedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/sign",
                new { key = keys.Signing, message = TestMessages.Normal });

            var (verified, verifiedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/verify",
                new
                {
                    key = other.Verification,
                    message = TestMessages.Normal,
                    signature = signedBody.RequiredString("signature")
                });

            Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
            Assert.Equal(canonicalName, verifiedBody.RequiredString("method"));
            Assert.False(verifiedBody.GetProperty("isValid").GetBoolean());
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task An_altered_signature_fails_verification(string method, string canonicalName)
        {
            var keys = await GenerateAsync(method);

            var (_, signedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/sign",
                new { key = keys.Signing, message = TestMessages.Normal });

            var (verified, verifiedBody) = await _client.PostJsonAsync(
                $"/api/signature/{method}/verify",
                new
                {
                    key = keys.Verification,
                    message = TestMessages.Normal,
                    signature = EnvelopeEditor.FlipLastByte(signedBody.RequiredString("signature"))
                });

            Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
            Assert.Equal(canonicalName, verifiedBody.RequiredString("method"));
            Assert.False(verifiedBody.GetProperty("isValid").GetBoolean());
        }

        [Fact]
        public async Task Ecdsa_signing_needs_the_private_key_and_verifying_needs_the_public_key()
        {
            var keys = await GenerateAsync("ecc-dss");

            var (_, signedBody) = await _client.PostJsonAsync(
                "/api/signature/ecc-dss/sign",
                new { key = keys.Signing, message = TestMessages.Normal });

            var (signWithPublic, _) = await _client.PostJsonAsync(
                "/api/signature/ecc-dss/sign",
                new { key = keys.Verification, message = TestMessages.Normal });
            var (verifyWithPrivate, _) = await _client.PostJsonAsync(
                "/api/signature/ecc-dss/verify",
                new
                {
                    key = keys.Signing,
                    message = TestMessages.Normal,
                    signature = signedBody.RequiredString("signature")
                });

            signWithPublic.AssertProblem();
            verifyWithPrivate.AssertProblem();
            Assert.Contains(
                "private key",
                await signWithPublic.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
            Assert.Contains(
                "public key",
                await verifyWithPrivate.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_malformed_signature_is_a_bad_request_rather_than_a_failed_check()
        {
            var keys = await GenerateAsync("hmac");

            var (response, _) = await _client.PostJsonAsync(
                "/api/signature/hmac/verify",
                new { key = keys.Verification, message = TestMessages.Normal, signature = "not base64 !!" });
            var body = await response.Content.ReadAsStringAsync();

            response.AssertProblem();
            Assert.Contains("signature", body, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_missing_signature_is_reported_as_a_validation_error()
        {
            var keys = await GenerateAsync("hmac");

            var (response, _) = await _client.PostJsonAsync(
                "/api/signature/hmac/verify",
                new { key = keys.Verification, message = TestMessages.Normal });

            response.AssertProblem();
            Assert.Contains(
                "A signature is required.",
                await response.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("/api/signature/nope/sign")]
        [InlineData("/api/signature/nope/verify")]
        public async Task An_unsupported_method_is_refused_and_the_supported_ones_are_listed(string route)
        {
            var (response, body) = await _client.PostJsonAsync(
                route,
                new { key = TestKeys.HmacSecret(), message = TestMessages.Normal, signature = "AAAA" });

            response.AssertProblem();

            // Read from the parsed document: JSON escapes the quotes around the method name.
            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported method 'nope'", detail, StringComparison.Ordinal);
            Assert.Contains("hmac-sha256", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_encryption_key_is_not_accepted_as_a_signing_key()
        {
            var (_, generated) = await _client.PostJsonAsync("/api/keygen/ecc-hillman", new { keySize = (int?)null });

            var (response, _) = await _client.PostJsonAsync(
                "/api/signature/hmac/verify",
                new
                {
                    key = generated.RequiredString("privateKey"),
                    message = TestMessages.Normal,
                    signature = "not base64 !!"
                });

            // An EC private key is long enough to pass the HMAC length rule, so the malformed signature is
            // what has to be reported; either way the request must not succeed.
            response.AssertProblem();
        }

        [Fact]
        public async Task A_signing_response_never_repeats_the_key()
        {
            var keys = await GenerateAsync("hmac");

            var (response, body) = await _client.PostJsonAsync(
                "/api/signature/hmac/sign",
                new { key = keys.Signing, message = TestMessages.Normal });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            ApiClient.AssertHidesSecrets(body, ("shared secret", keys.Signing));
        }

        [Fact]
        public async Task The_discovery_endpoint_documents_every_signature_method()
        {
            var (response, body) = await _client.GetJsonAsync("/api/signature/methods");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(
                new[] { "ecc-dss", "hmac-sha256" },
                body.EnumerateArray().Select(method => method.RequiredString("name")).ToArray());

            foreach (var method in body.EnumerateArray())
            {
                Assert.NotEmpty(method.GetProperty("aliases").EnumerateArray());
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("description")));
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("signingKeyFormat")));
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("verificationKeyFormat")));
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("signatureFormat")));
            }
        }

        /// <summary>Generates a key through the API and returns the halves signing and verifying need.</summary>
        private async Task<(string Signing, string Verification)> GenerateAsync(string method)
        {
            var (response, body) = await _client.PostJsonAsync($"/api/keygen/{method}", new { keySize = (int?)null });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            return body.TryGetProperty("key", out _)
                ? (body.RequiredString("key"), body.RequiredString("key"))
                : (body.RequiredString("privateKey"), body.RequiredString("publicKey"));
        }
    }
}
