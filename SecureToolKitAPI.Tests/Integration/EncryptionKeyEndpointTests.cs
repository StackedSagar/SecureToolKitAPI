using System.Net;
using System.Text.Json;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The encryption key generation endpoints over HTTP: that every route answers with and without a body,
    /// that the options in the body are applied, that unusable options become a problem response rather than
    /// an exception, and that the routes these were added alongside still behave as they did.
    /// </summary>
    /// <remarks>
    /// Every response here except the salt carries live key material, so no assertion prints a generated
    /// value: they check shape, length and byte count, and compare values through a boolean. Nothing here
    /// sends a secret to the API except a key it just generated, so nothing here can leak a stored one.
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class EncryptionKeyEndpointTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>The symmetric routes, with the algorithm and default size each one reports.</summary>
        public static TheoryData<string, string, int> SymmetricRoutes => new()
        {
            { "/api/encryption/aes", "AES-GCM", 256 },
            { "/api/encryption/aes-256", "AES-GCM", 256 },
            { "/api/encryption/hmac", "HMAC-SHA256", 256 },
            { "/api/encryption/secret", "Random-Secret", 256 }
        };

        [Theory]
        [MemberData(nameof(SymmetricRoutes))]
        public async Task Each_symmetric_route_answers_without_a_body_and_uses_its_documented_default(
            string route,
            string algorithm,
            int defaultKeySize)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(algorithm, body.RequiredString("algorithm"));
            Assert.Equal(defaultKeySize, body.GetProperty("keySize").GetInt32());
            Assert.Equal(defaultKeySize / 8, Convert.FromBase64String(body.RequiredString("key")).Length);
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("keyFormat")));
            Assert.Equal(JsonValueKind.Array, body.GetProperty("warnings").ValueKind);

            // A symmetric route must never hand back half of a key pair in place of a key.
            Assert.False(body.TryGetProperty("publicKey", out _));
            Assert.False(body.TryGetProperty("privateKey", out _));
        }

        [Fact]
        public async Task The_rsa_route_answers_without_a_body_and_returns_a_2048_bit_pair()
        {
            var response = await _client.PostAsync("/api/encryption/rsa", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("RSA-OAEP", body.RequiredString("algorithm"));
            Assert.Equal(2048, body.GetProperty("keySize").GetInt32());
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("publicKey")));
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("privateKey")));

            // A pair route must never return the private key in the field symmetric callers read.
            Assert.False(body.TryGetProperty("key", out _));
        }

        [Fact]
        public async Task The_general_route_defaults_to_a_256_bit_aes_key_which_is_what_an_encryption_key_means()
        {
            var response = await _client.PostAsync("/api/encryption/encryption-key", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("aes", body.RequiredString("method"));
            Assert.Equal("AES-GCM", body.RequiredString("algorithm"));
            Assert.Equal(256, body.GetProperty("keySize").GetInt32());
            Assert.Equal(32, Convert.FromBase64String(body.RequiredString("key")).Length);
        }

        [Theory]
        [InlineData("aes", "AES-GCM")]
        [InlineData("AES", "AES-GCM")]
        [InlineData("aes-gcm", "AES-GCM")]
        [InlineData("ecc-hillman", "ECC-Hillman")]
        [InlineData("ecdh", "ECC-Hillman")]
        [InlineData("ecc-dss", "ECC-DSA")]
        [InlineData("hmac", "HMAC-SHA256")]
        [InlineData("SECRET", "Random-Secret")]
        public async Task The_general_route_reaches_every_documented_method(string method, string algorithm)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/encryption/encryption-key",
                new { method });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            // The method is echoed in its canonical spelling, so a caller can tell what it actually got.
            Assert.Equal(method.ToLowerInvariant(), body.RequiredString("method"));
            Assert.Equal(algorithm, body.RequiredString("algorithm"));
            Assert.True(
                body.TryGetProperty("key", out _) || body.TryGetProperty("publicKey", out _),
                "The response carried neither a symmetric key nor a public key.");
        }

        [Fact]
        public async Task The_general_route_applies_the_key_size_it_was_given()
        {
            // The smallest supported RSA size keeps the test quick; the encryption endpoints reject it.
            var (response, body) = await _client.PostJsonAsync(
                "/api/encryption/encryption-key",
                new { method = "rsa", keySize = 512 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("rsa", body.RequiredString("method"));
            Assert.Equal(512, body.GetProperty("keySize").GetInt32());
            Assert.NotEmpty(body.GetProperty("warnings").EnumerateArray());
        }

        [Theory]
        [InlineData("/api/encryption/aes", 128)]
        [InlineData("/api/encryption/aes", 192)]
        [InlineData("/api/encryption/hmac", 512)]
        [InlineData("/api/encryption/secret", 1024)]
        public async Task A_requested_key_size_is_honoured(string route, int keySize)
        {
            var (response, body) = await _client.PostJsonAsync(route, new { keySize });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(keySize, body.GetProperty("keySize").GetInt32());
            Assert.Equal(keySize / 8, Convert.FromBase64String(body.RequiredString("key")).Length);
        }

        [Fact]
        public async Task The_rsa_route_applies_the_key_size_it_was_given()
        {
            var (response, body) = await _client.PostJsonAsync("/api/encryption/rsa", new { keySize = 1024 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(1024, body.GetProperty("keySize").GetInt32());
        }

        [Fact]
        public async Task The_fixed_size_route_stays_at_256_bits_whatever_it_is_sent()
        {
            // The size is not a parameter of this route, so a body asking for another one changes nothing.
            var (response, body) = await _client.PostJsonAsync("/api/encryption/aes-256", new { keySize = 128 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(256, body.GetProperty("keySize").GetInt32());
            Assert.Equal(32, Convert.FromBase64String(body.RequiredString("key")).Length);
        }

        [Theory]
        [InlineData("/api/encryption/aes", 200)]
        [InlineData("/api/encryption/aes", 64)]
        [InlineData("/api/encryption/rsa", 777)]
        [InlineData("/api/encryption/hmac", 64)]
        [InlineData("/api/encryption/secret", 300)]
        public async Task An_unsupported_key_size_is_refused_with_a_problem_response(string route, int keySize)
        {
            var (response, body) = await _client.PostJsonAsync(route, new { keySize });

            response.AssertProblem();
            Assert.Contains("Supported sizes are", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unsupported_method_is_refused_and_the_supported_ones_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/encryption/encryption-key",
                new { method = "blowfish" });

            response.AssertProblem();

            // Read from the parsed document: JSON escapes the quotes around the method name.
            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported method 'blowfish'", detail, StringComparison.Ordinal);
            Assert.Contains("aes", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_problem_response_says_what_was_wrong_and_nothing_about_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync("/api/encryption/aes", new { keySize = 200 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("SecureToolKitAPI.", detail, StringComparison.Ordinal);
            Assert.DoesNotContain("Exception", detail, StringComparison.Ordinal);
            Assert.DoesNotContain(" at ", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_salt_route_answers_without_a_body_and_defaults_to_16_bytes_of_base64()
        {
            var response = await _client.PostAsync("/api/encryption/salt", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(16, body.GetProperty("bytes").GetInt32());
            Assert.Equal(16, Convert.FromBase64String(body.RequiredString("value")).Length);
            Assert.Equal("Base64 encoded, 16 random bytes.", body.RequiredString("format"));

            // A salt is not key material, so it must not be dressed up as any.
            Assert.False(body.TryGetProperty("key", out _));
            Assert.False(body.TryGetProperty("privateKey", out _));
        }

        [Theory]
        [InlineData("base64", 16, 24)]
        [InlineData("base64", 32, 44)]
        [InlineData("base64url", 16, 22)]
        [InlineData("hex", 16, 32)]
        [InlineData("hexUpper", 32, 64)]
        [InlineData("HEX_UPPER", 8, 16)]
        public async Task A_salt_is_rendered_in_the_size_and_encoding_that_were_asked_for(
            string encoding,
            int bytes,
            int expectedLength)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/encryption/salt",
                new { bytes, encoding });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(bytes, body.GetProperty("bytes").GetInt32());
            Assert.Equal(expectedLength, body.RequiredString("value").Length);
        }

        [Fact]
        public async Task The_salt_response_says_that_a_salt_must_be_stored_and_never_reused()
        {
            var (response, body) = await _client.PostJsonAsync("/api/encryption/salt", new { bytes = 32 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var warnings = body.GetProperty("warnings").EnumerateArray().Select(warning => warning.GetString()!).ToArray();

            Assert.Equal(3, warnings.Length);
            Assert.Contains(warnings, warning => warning.Contains("must be stored with the", StringComparison.Ordinal));
            Assert.Contains(warnings, warning => warning.Contains("new salt for every value hashed", StringComparison.Ordinal));
            Assert.Contains(
                warnings,
                warning => warning.Contains("not a substitute for a password-hashing function", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(65)]
        [InlineData(-16)]
        public async Task A_salt_size_outside_the_supported_range_is_a_bad_request(int bytes)
        {
            var (response, body) = await _client.PostJsonAsync("/api/encryption/salt", new { bytes });

            response.AssertProblem();
            Assert.Contains("between 8 and 64 bytes", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_base62_salt_is_refused_because_it_could_not_be_decoded_to_verify_a_hash()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/encryption/salt",
                new { encoding = "base62" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("not a byte encoding", detail, StringComparison.Ordinal);
            Assert.Contains("Base64, Base64Url, Hex, HexUpper", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unknown_salt_encoding_is_refused_and_the_supported_ones_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/encryption/salt",
                new { encoding = "base99" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported encoding 'base99'", detail, StringComparison.Ordinal);
            Assert.Contains("Base64", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("/api/encryption/aes")]
        [InlineData("/api/encryption/secret")]
        [InlineData("/api/encryption/salt")]
        public async Task These_routes_are_not_reachable_by_get_so_no_value_can_travel_in_a_url(string route)
        {
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Two_calls_never_return_the_same_key_or_the_same_salt()
        {
            var firstKey = await _client.PostAsync("/api/encryption/aes-256", content: null);
            var secondKey = await _client.PostAsync("/api/encryption/aes-256", content: null);
            var firstSalt = await _client.PostAsync("/api/encryption/salt", content: null);
            var secondSalt = await _client.PostAsync("/api/encryption/salt", content: null);

            var keys = (await ApiClient.ReadJsonAsync(firstKey), await ApiClient.ReadJsonAsync(secondKey));
            var salts = (await ApiClient.ReadJsonAsync(firstSalt), await ApiClient.ReadJsonAsync(secondSalt));

            // Compared through a boolean, because one of the two pairs is live key material.
            Assert.False(
                string.Equals(keys.Item1.RequiredString("key"), keys.Item2.RequiredString("key"), StringComparison.Ordinal),
                "Two key generation calls returned the same key, so the randomness is not working.");
            Assert.False(
                string.Equals(salts.Item1.RequiredString("value"), salts.Item2.RequiredString("value"), StringComparison.Ordinal),
                "Two salt calls returned the same salt, which is the one thing a salt must never do.");
        }

        [Fact]
        public async Task A_key_generated_here_is_usable_for_its_own_algorithm()
        {
            var generated = await _client.PostAsync("/api/encryption/aes-256", content: null);
            var key = (await ApiClient.ReadJsonAsync(generated)).RequiredString("key");

            var (encrypted, encryptedBody) = await _client.PostJsonAsync(
                "/api/encrypt/aes",
                new { key, message = TestMessages.Normal });

            Assert.Equal(HttpStatusCode.OK, encrypted.StatusCode);

            var (decrypted, decryptedBody) = await _client.PostJsonAsync(
                "/api/decrypt/aes",
                new { key, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });

            Assert.Equal(HttpStatusCode.OK, decrypted.StatusCode);
            Assert.Equal(TestMessages.Normal, decryptedBody.RequiredString("message"));
        }

        [Theory]
        [InlineData("/api/keygen/aes", "/api/encryption/aes", "AES-GCM")]
        [InlineData("/api/keygen/hmac", "/api/encryption/hmac", "HMAC-SHA256")]
        [InlineData("/api/keygen/random", "/api/encryption/secret", "Random-Secret")]
        public async Task The_original_get_routes_still_answer_and_report_the_same_algorithm(
            string legacyRoute,
            string route,
            string algorithm)
        {
            // The two controllers share one generator and one mapper, so the newer route must not have
            // changed what the older one returns.
            var (legacy, legacyBody) = await _client.GetJsonAsync(legacyRoute);

            var current = await _client.PostAsync(route, content: null);
            var currentBody = await ApiClient.ReadJsonAsync(current);

            Assert.Equal(HttpStatusCode.OK, legacy.StatusCode);
            Assert.Equal(HttpStatusCode.OK, current.StatusCode);
            Assert.Equal(algorithm, legacyBody.RequiredString("algorithm"));
            Assert.Equal(algorithm, currentBody.RequiredString("algorithm"));
            Assert.Equal(
                legacyBody.GetProperty("keySize").GetInt32(),
                currentBody.GetProperty("keySize").GetInt32());
            Assert.Equal(legacyBody.RequiredString("keyFormat"), currentBody.RequiredString("keyFormat"));
        }
    }
}
