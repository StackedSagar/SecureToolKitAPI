using System.Net;
using System.Text;
using System.Text.Json;
using SecureToolKitAPI.Application;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The developer secret endpoints over HTTP: that every route answers with and without a body, that the
    /// options in the body are applied, that unusable options become a problem response rather than an
    /// exception, and that the provider listing exposes no secret.
    /// </summary>
    /// <remarks>
    /// Generated values are never asserted against a fixed expectation and never printed: the assertions
    /// check shape, length and character class. Nothing here sends a secret to the API, so nothing here can
    /// leak one.
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class DeveloperEndpointTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>Every route that returns a single secret, with the length it defaults to.</summary>
        public static TheoryData<string, int> SecretRoutes => new()
        {
            { "/api/developer/api-key", 43 },
            { "/api/developer/jwt-secret", 44 },
            { "/api/developer/oauth-token", 43 },
            { "/api/developer/ai-key", 46 },
            { "/api/developer/random-string", 32 }
        };

        [Theory]
        [MemberData(nameof(SecretRoutes))]
        public async Task Each_secret_route_answers_without_a_body_and_uses_its_documented_default(
            string route,
            int expectedLength)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expectedLength, body.GetProperty("length").GetInt32());
            Assert.Equal(expectedLength, body.RequiredString("value").Length);
            Assert.True(body.GetProperty("entropyBits").GetDouble() > 0d, "The response reported no entropy.");
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("strength")), "The strength was missing.");
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("composition")), "The composition was missing.");
        }

        [Theory]
        [InlineData("base64url", 43)]
        [InlineData("base64", 44)]
        [InlineData("hex", 64)]
        [InlineData("hexUpper", 64)]
        [InlineData("base62", 43)]
        [InlineData("BASE64_URL", 43)]
        public async Task An_api_key_is_rendered_in_the_encoding_that_was_asked_for(string encoding, int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/api-key", new { encoding });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.RequiredString("value").Length);
            Assert.Equal(256d, body.GetProperty("entropyBits").GetDouble());
        }

        [Theory]
        [InlineData(16, 22)]
        [InlineData(32, 43)]
        [InlineData(64, 86)]
        [InlineData(128, 171)]
        public async Task The_requested_size_is_applied(int bytes, int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/api-key", new { bytes });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.RequiredString("value").Length);
            Assert.Equal(bytes * 8d, body.GetProperty("entropyBits").GetDouble());
        }

        [Fact]
        public async Task A_prefix_is_applied_and_described_only_by_its_length()
        {
            const string prefix = "sk_live_";

            var (response, body) = await _client.PostJsonAsync("/api/developer/api-key", new { prefix });

            var value = body.RequiredString("value");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(
                value.StartsWith(prefix, StringComparison.Ordinal),
                "The returned key did not begin with the requested prefix.");
            Assert.Equal(prefix.Length + 43, value.Length);

            var composition = body.RequiredString("composition");

            Assert.Contains($"behind a {prefix.Length} character prefix", composition, StringComparison.Ordinal);
            Assert.DoesNotContain(prefix, composition, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(15)]
        [InlineData(0)]
        [InlineData(-8)]
        [InlineData(129)]
        public async Task A_size_outside_the_supported_range_is_a_bad_request(int bytes)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/api-key", new { bytes });

            response.AssertProblem();
            Assert.Contains("between 16 and 128 bytes", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("sk live ")]
        [InlineData("sk/live/")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaa")]
        public async Task A_prefix_that_would_not_survive_a_url_is_a_bad_request(string prefix)
        {
            var (response, _) = await _client.PostJsonAsync("/api/developer/api-key", new { prefix });

            response.AssertProblem();
        }

        [Fact]
        public async Task An_unknown_encoding_is_refused_and_the_supported_names_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/api-key",
                new { encoding = "rot13" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported encoding", detail, StringComparison.Ordinal);
            Assert.Contains("Base64Url", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_rejected_request_is_explained_without_exposing_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/api-key", new { bytes = 9999 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("Exception", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SecureToolKitAPI", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("HS256", 44)]
        [InlineData("hs384", 64)]
        [InlineData("HS512", 88)]
        public async Task A_jwt_secret_is_sized_for_the_algorithm_it_will_sign_with(string algorithm, int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/jwt-secret", new { algorithm });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.RequiredString("value").Length);

            // The catalogue's own spelling is echoed back, not the caller's.
            Assert.Equal(algorithm, body.RequiredString("kind"), ignoreCase: true);
            Assert.Contains("HMAC key", body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_jwt_secret_says_that_whoever_can_verify_a_token_can_also_mint_one()
        {
            var response = await _client.PostAsync("/api/developer/jwt-secret", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("symmetric", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task An_unknown_jwt_algorithm_is_refused_and_the_supported_names_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/jwt-secret",
                new { algorithm = "none" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported JWT algorithm", detail, StringComparison.Ordinal);
            Assert.Contains("HS256", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("accessToken", 43, "bearer credential")]
        [InlineData("refresh-token", 86, "rotate it on every use")]
        [InlineData("CLIENT_SECRET", 64, "PKCE")]
        [InlineData("authorizationCode", 43, "single use")]
        public async Task An_oauth_value_is_sized_and_explained_according_to_its_kind(
            string kind,
            int length,
            string expectedAdvice)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/oauth-token", new { kind });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.RequiredString("value").Length);
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("kind")), "The token kind was not reported.");

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains(expectedAdvice, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task An_oauth_size_the_caller_asks_for_overrides_the_default_for_the_kind()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/oauth-token",
                new { kind = "refreshToken", bytes = 32 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(256d, body.GetProperty("entropyBits").GetDouble());
        }

        [Fact]
        public async Task An_unknown_oauth_kind_is_refused_and_the_supported_names_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/oauth-token",
                new { kind = "id-token" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported token kind", detail, StringComparison.Ordinal);
            Assert.Contains("RefreshToken", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_provider_listing_describes_every_provider_and_contains_no_generated_value()
        {
            var (response, body) = await _client.GetJsonAsync("/api/developer/ai-key/providers");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var providers = body.EnumerateArray().ToArray();

            Assert.Equal(AiKeyProviderCatalog.All.Count, providers.Length);

            // Ordered by name, so the listing is stable for a caller that renders it as-is.
            Assert.Equal(
                AiKeyProviderCatalog.Names,
                providers.Select(provider => provider.RequiredString("name")).ToArray());

            Assert.All(providers, provider =>
            {
                Assert.False(
                    string.IsNullOrWhiteSpace(provider.RequiredString("displayName")),
                    "A provider had no display name.");

                Assert.False(
                    string.IsNullOrWhiteSpace(provider.RequiredString("description")),
                    "A provider had no description.");

                Assert.True(provider.GetProperty("bytes").GetInt32() >= 16, "A provider reported an unusable size.");

                // Describing a provider must not require generating a key, so there is nothing secret in
                // this response.
                Assert.False(provider.TryGetProperty("value", out _), "The provider listing returned a generated key.");

                Assert.Contains(
                    Warnings(provider),
                    warning => warning.Contains("only imitates", StringComparison.Ordinal));
            });
        }

        [Theory]
        [InlineData("openai", 46)]
        [InlineData("anthropic", 72)]
        [InlineData("azure-openai", 32)]
        [InlineData("google-ai", 47)]
        [InlineData("Cohere", 43)]
        public async Task An_ai_key_has_the_shape_of_the_named_provider(string provider, int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/ai-key", new { provider });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.RequiredString("value").Length);

            // The catalogue's own spelling is echoed back, not the caller's.
            Assert.Equal(provider, body.RequiredString("kind"), ignoreCase: true);
            Assert.Contains(body.RequiredString("kind"), AiKeyProviderCatalog.Names);
        }

        [Fact]
        public async Task An_ai_key_always_says_it_is_not_a_working_provider_credential()
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/ai-key", new { provider = "openai" });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var warnings = Warnings(body);

            // First, so it cannot be missed by a caller that shows only one advisory.
            Assert.Contains("only imitates", warnings[0], StringComparison.Ordinal);
            Assert.Contains("will not authenticate", warnings[0], StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_ai_key_without_a_named_provider_uses_the_generic_format()
        {
            var response = await _client.PostAsync("/api/developer/ai-key", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("generic", body.RequiredString("kind"));
            Assert.True(
                body.RequiredString("value").StartsWith("ai_", StringComparison.Ordinal),
                "The generic AI key did not carry the 'ai_' prefix.");
        }

        [Fact]
        public async Task An_unknown_provider_is_refused_and_the_supported_names_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/ai-key",
                new { provider = "not-a-provider" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported provider", detail, StringComparison.Ordinal);
            Assert.Contains("openai", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_webauthn_route_returns_two_independent_values_with_their_sizes()
        {
            var response = await _client.PostAsync("/api/developer/webauthn-credential", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(32, body.GetProperty("challengeBytes").GetInt32());
            Assert.Equal(64, body.GetProperty("userHandleBytes").GetInt32());

            var challenge = body.RequiredString("challenge");
            var userHandle = body.RequiredString("userHandle");

            Assert.Equal(43, challenge.Length);
            Assert.Equal(86, userHandle.Length);
            Assert.True(
                !string.Equals(challenge, userHandle, StringComparison.Ordinal),
                "The challenge and the user handle were the same value, so one of them was reused.");

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("credential ID", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task The_requested_webauthn_sizes_are_applied()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/webauthn-credential",
                new { challengeBytes = 16, userHandleBytes = 32 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(16, body.GetProperty("challengeBytes").GetInt32());
            Assert.Equal(22, body.RequiredString("challenge").Length);
            Assert.Equal(43, body.RequiredString("userHandle").Length);
        }

        [Theory]
        [InlineData(8, 64)]
        [InlineData(32, 128)]
        public async Task A_webauthn_size_outside_the_supported_range_is_a_bad_request(
            int challengeBytes,
            int userHandleBytes)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/webauthn-credential",
                new { challengeBytes, userHandleBytes });

            response.AssertProblem();
            Assert.Contains("between 16 and 64 bytes", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("digits", 8)]
        [InlineData("hex", 40)]
        [InlineData("base64url", 64)]
        [InlineData("lowercase", 100)]
        public async Task A_random_string_uses_the_requested_length_and_alphabet(string alphabet, int length)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/random-string",
                new { length, alphabet });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.RequiredString("value").Length);
            Assert.Contains($"{length} characters sampled from", body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_custom_alphabet_is_the_only_thing_a_random_string_is_sampled_from()
        {
            const string alphabet = "ACEFGHJKLMNPQRTUVWXY34679";

            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/random-string",
                new { length = 32, alphabet = "custom", customAlphabet = alphabet });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.True(
                body.RequiredString("value").All(character => alphabet.Contains(character, StringComparison.Ordinal)),
                "A random string contained a character from outside the supplied alphabet.");

            // The alphabet is caller-supplied, so it is described rather than echoed back.
            Assert.DoesNotContain(alphabet, body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_custom_alphabet_supplied_without_asking_for_custom_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/random-string",
                new { alphabet = "hex", customAlphabet = "abcdef" });

            response.AssertProblem();
            Assert.Contains("Set the alphabet to 'custom'", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4097)]
        public async Task A_random_string_length_outside_the_supported_range_is_a_bad_request(int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/developer/random-string", new { length });

            response.AssertProblem();
            Assert.Contains("between 1 and 4096 characters", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unknown_alphabet_is_refused_and_the_supported_names_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/developer/random-string",
                new { alphabet = "emoji" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported alphabet", detail, StringComparison.Ordinal);
            Assert.Contains("Alphanumeric", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_vapid_route_returns_a_p256_pair_in_both_the_raw_and_the_pem_forms()
        {
            var response = await _client.PostAsync("/api/developer/vapid-key", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("P-256", body.RequiredString("curve"));

            // 65 raw bytes for the uncompressed point and 32 for the scalar, Base64url without padding.
            Assert.Equal(87, body.RequiredString("publicKey").Length);
            Assert.Equal(43, body.RequiredString("privateKey").Length);

            Assert.True(
                body.RequiredString("publicKeyPem").StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal),
                "The public key was not returned as a SubjectPublicKeyInfo PEM.");

            // Asserted through a boolean so a failure cannot print the private key.
            Assert.True(
                body.RequiredString("privateKeyPem").StartsWith("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal),
                "The private key was not returned as a PKCS#8 PEM.");

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("invalidates every existing push subscription", StringComparison.Ordinal));
        }

        [Fact]
        public async Task Repeated_requests_do_not_return_the_same_secret()
        {
            var values = new List<string>();

            for (var attempt = 0; attempt < 10; attempt++)
            {
                var (_, body) = await _client.PostJsonAsync("/api/developer/api-key", new { bytes = 32 });
                values.Add(body.RequiredString("value"));
            }

            // Only the counts are compared, so no generated value reaches the test output.
            Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
        }

        [Theory]
        [InlineData("/api/developer/api-key")]
        [InlineData("/api/developer/jwt-secret")]
        [InlineData("/api/developer/vapid-key")]
        public async Task A_get_request_to_a_generation_route_is_not_allowed(string route)
        {
            // Nothing sensitive may be produced by a URL a browser or a proxy will log.
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/developer/api-key",
                new StringContent("{\"bytes\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }

        /// <summary>The warnings from a response, as plain strings.</summary>
        /// <param name="body">The parsed response body or provider entry.</param>
        private static string[] Warnings(JsonElement body) =>
            [.. body.GetProperty("warnings").EnumerateArray().Select(warning => warning.GetString() ?? string.Empty)];
    }
}
