using System.Net;
using System.Text.Json;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// Key generation over HTTP. The GET routes existed before this API gained encryption, so their shape is
    /// asserted field by field: changing it would break callers that already depend on it.
    /// </summary>
    [Collection(ApiCollection.Name)]
    public class KeyGenerationEndpointTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>The original symmetric routes, with the key size each one has always defaulted to.</summary>
        public static TheoryData<string, string, int> SymmetricRoutes => new()
        {
            { "/api/keygen/aes", "AES-GCM", 256 },
            { "/api/keygen/hmac", "HMAC-SHA256", 256 },
            { "/api/keygen/random", "Random-Secret", 256 }
        };

        /// <summary>The original key pair routes, with the key size each one has always defaulted to.</summary>
        public static TheoryData<string, int> KeyPairRoutes => new()
        {
            { "/api/keygen/rsa", 2048 },
            { "/api/keygen/EccHillman", 256 },
            { "/api/keygen/EccDss", 256 }
        };

        [Theory]
        [MemberData(nameof(SymmetricRoutes))]
        public async Task The_original_symmetric_routes_keep_their_response_shape(
            string route,
            string algorithm,
            int defaultKeySize)
        {
            var (response, body) = await _client.GetJsonAsync(route);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(algorithm, body.RequiredString("algorithm"));
            Assert.Equal(defaultKeySize, body.GetProperty("keySize").GetInt32());
            Assert.Equal(defaultKeySize / 8, Convert.FromBase64String(body.RequiredString("key")).Length);
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("keyFormat")));
            Assert.Equal(JsonValueKind.Array, body.GetProperty("warnings").ValueKind);
        }

        [Theory]
        [MemberData(nameof(KeyPairRoutes))]
        public async Task The_original_key_pair_routes_keep_their_response_shape(string route, int defaultKeySize)
        {
            var (response, body) = await _client.GetJsonAsync(route);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("algorithm")));
            Assert.Equal(defaultKeySize, body.GetProperty("keySize").GetInt32());
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("publicKey")));
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("privateKey")));
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("keyFormat")));
            Assert.Equal(JsonValueKind.Array, body.GetProperty("warnings").ValueKind);

            // A pair endpoint must never return the private key in the field symmetric callers read.
            Assert.False(body.TryGetProperty("key", out _));
        }

        [Theory]
        [InlineData("/api/keygen/aes?keySize=128", 128)]
        [InlineData("/api/keygen/aes?keySize=192", 192)]
        [InlineData("/api/keygen/hmac?keySize=512", 512)]
        [InlineData("/api/keygen/random?keySize=1024", 1024)]
        public async Task A_requested_key_size_is_honoured(string route, int keySize)
        {
            var (response, body) = await _client.GetJsonAsync(route);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(keySize, body.GetProperty("keySize").GetInt32());
            Assert.Equal(keySize / 8, Convert.FromBase64String(body.RequiredString("key")).Length);
        }

        [Fact]
        public async Task The_route_names_stay_case_insensitive_for_existing_callers()
        {
            var (mixedCase, _) = await _client.GetJsonAsync("/api/keygen/EccHillman");
            var (lowerCase, _) = await _client.GetJsonAsync("/api/keygen/ecchillman");

            Assert.Equal(HttpStatusCode.OK, mixedCase.StatusCode);
            Assert.Equal(HttpStatusCode.OK, lowerCase.StatusCode);
        }

        [Theory]
        [InlineData("/api/keygen/aes?keySize=200")]
        [InlineData("/api/keygen/rsa?keySize=777")]
        [InlineData("/api/keygen/EccDss?keySize=128")]
        [InlineData("/api/keygen/hmac?keySize=64")]
        public async Task An_unsupported_key_size_is_refused_with_a_problem_response(string route)
        {
            var response = await _client.GetAsync(route);
            var body = await response.Content.ReadAsStringAsync();

            response.AssertProblem();
            Assert.Contains("Supported sizes are", body, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("aes")]
        [InlineData("aes-gcm")]
        [InlineData("rsa")]
        [InlineData("ecc-hillman")]
        [InlineData("ecdh")]
        [InlineData("ecc-dss")]
        [InlineData("ecdsa")]
        [InlineData("hmac")]
        [InlineData("random")]
        [InlineData("SECRET")]
        public async Task Every_documented_identifier_can_be_generated_through_the_post_route(string method)
        {
            // The smallest supported RSA size keeps the test quick; it is rejected for encryption elsewhere.
            var keySize = method is "rsa" ? 512 : (int?)null;

            var (response, body) = await _client.PostJsonAsync($"/api/keygen/{method}", new { keySize });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(method.Trim().ToLowerInvariant(), body.RequiredString("method"));
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("algorithm")));
            Assert.True(body.GetProperty("keySize").GetInt32() > 0);
            Assert.True(
                body.TryGetProperty("key", out _) || body.TryGetProperty("publicKey", out _),
                "The response carried neither a symmetric key nor a public key.");
        }

        [Fact]
        public async Task The_post_route_uses_the_method_default_when_no_body_is_sent()
        {
            var response = await _client.PostAsync("/api/keygen/aes", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(256, body.GetProperty("keySize").GetInt32());
        }

        [Fact]
        public async Task A_generated_key_pair_omits_the_symmetric_key_field_and_a_secret_omits_the_pair_fields()
        {
            var (_, pair) = await _client.PostJsonAsync("/api/keygen/ecc-dss", new { keySize = (int?)null });
            var (_, secret) = await _client.PostJsonAsync("/api/keygen/hmac", new { keySize = (int?)null });

            Assert.False(pair.TryGetProperty("key", out _));
            Assert.True(pair.TryGetProperty("privateKey", out _));
            Assert.False(secret.TryGetProperty("publicKey", out _));
            Assert.False(secret.TryGetProperty("privateKey", out _));
        }

        [Fact]
        public async Task An_unsupported_method_is_refused_and_the_supported_ones_are_listed()
        {
            var (response, body) = await _client.PostJsonAsync("/api/keygen/blowfish", new { keySize = (int?)null });

            response.AssertProblem();

            // Read from the parsed document: JSON escapes the quotes around the method name.
            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported method 'blowfish'", detail, StringComparison.Ordinal);
            Assert.Contains("aes", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Two_calls_never_return_the_same_key()
        {
            var (_, first) = await _client.GetJsonAsync("/api/keygen/aes");
            var (_, second) = await _client.GetJsonAsync("/api/keygen/aes");

            // Compared without printing either key, because both are live secrets.
            Assert.False(
                string.Equals(first.RequiredString("key"), second.RequiredString("key"), StringComparison.Ordinal),
                "Two key generation calls returned the same key, so the randomness is not working.");
        }

        [Fact]
        public async Task The_discovery_endpoint_documents_every_generator()
        {
            var (response, body) = await _client.GetJsonAsync("/api/keygen/methods");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var names = body.EnumerateArray().Select(method => method.RequiredString("name")).ToArray();

            Assert.Equal(new[] { "aes", "ecc-dss", "ecc-hillman", "hmac", "random", "rsa" }, names);

            foreach (var method in body.EnumerateArray())
            {
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("description")));
                Assert.NotEmpty(method.GetProperty("aliases").EnumerateArray());
                Assert.NotEmpty(method.GetProperty("supportedKeySizes").EnumerateArray());
                Assert.True(method.GetProperty("defaultKeySize").GetInt32() > 0);
            }
        }

        [Fact]
        public async Task A_generator_that_needs_a_warning_returns_one()
        {
            // 512-bit RSA is offered for compatibility only, so the response has to say so.
            var (response, body) = await _client.PostJsonAsync("/api/keygen/rsa", new { keySize = 512 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.NotEmpty(body.GetProperty("warnings").EnumerateArray());
        }

        [Fact]
        public async Task A_generated_key_is_usable_for_its_own_algorithm()
        {
            var (_, generated) = await _client.PostJsonAsync("/api/keygen/aes", new { keySize = (int?)null });

            var (encrypted, encryptedBody) = await _client.PostJsonAsync(
                "/api/encrypt/aes",
                new { key = generated.RequiredString("key"), message = TestMessages.Normal });

            Assert.Equal(HttpStatusCode.OK, encrypted.StatusCode);
            Assert.False(string.IsNullOrWhiteSpace(encryptedBody.RequiredString("encryptedMessage")));
        }
    }
}
