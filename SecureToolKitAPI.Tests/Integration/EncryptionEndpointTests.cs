using System.Net;
using System.Text;
using System.Text.Json;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The flow the specification asks for, end to end over HTTP: generate a secret, encrypt a message,
    /// decrypt it and get the original message back. The error paths assert that failures stay safe.
    /// </summary>
    [Collection(ApiCollection.Name)]
    public class EncryptionEndpointTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>Identifiers that name the same algorithm to the key generation and encryption endpoints.</summary>
        public static TheoryData<string> Methods => new() { "aes", "rsa", "ecc-hillman" };

        /// <summary>Every method paired with every message all three methods can carry.</summary>
        public static TheoryData<string, string> MethodsAndMessages
        {
            get
            {
                var data = new TheoryData<string, string>();

                foreach (var method in new[] { "aes", "rsa", "ecc-hillman" })
                {
                    foreach (var message in TestMessages.UniversallySupported())
                    {
                        data.Add(method, message);
                    }
                }

                return data;
            }
        }

        [Theory]
        [MemberData(nameof(MethodsAndMessages))]
        public async Task Generate_then_encrypt_then_decrypt_returns_the_original_message(string method, string message)
        {
            var keys = await GenerateAsync(method);

            var (encrypted, encryptedBody) = await _client.PostJsonAsync(
                $"/api/encrypt/{method}",
                new { key = keys.Encryption, message });

            Assert.Equal(HttpStatusCode.OK, encrypted.StatusCode);

            var (decrypted, decryptedBody) = await _client.PostJsonAsync(
                $"/api/decrypt/{method}",
                new { key = keys.Decryption, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });

            Assert.Equal(HttpStatusCode.OK, decrypted.StatusCode);
            Assert.Equal(message, decryptedBody.GetProperty("message").GetString());
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task The_encrypt_response_names_the_method_and_documents_its_envelope(string method)
        {
            var keys = await GenerateAsync(method);

            var (_, body) = await _client.PostJsonAsync(
                $"/api/encrypt/{method}",
                new { key = keys.Encryption, message = TestMessages.Normal });

            // The canonical name is returned even when the caller used an alias, so the value can be
            // fed straight back into the decrypt endpoint.
            Assert.Contains(body.RequiredString("method"), new[] { "aes-gcm", "rsa-oaep", "ecc-hillman" });
            Assert.Contains("version(1)", body.RequiredString("envelopeLayout"), StringComparison.Ordinal);
            Assert.Equal(JsonValueKind.Object, body.GetProperty("parameters").ValueKind);
        }

        [Fact]
        public async Task The_reported_parameters_match_what_each_method_actually_uses()
        {
            var aes = await GenerateAsync("aes");
            var ecdh = await GenerateAsync("ecc-hillman");
            var rsa = await GenerateAsync("rsa");

            var (_, aesBody) = await _client.PostJsonAsync(
                "/api/encrypt/aes", new { key = aes.Encryption, message = TestMessages.Normal });
            var (_, ecdhBody) = await _client.PostJsonAsync(
                "/api/encrypt/ecc-hillman", new { key = ecdh.Encryption, message = TestMessages.Normal });
            var (_, rsaBody) = await _client.PostJsonAsync(
                "/api/encrypt/rsa", new { key = rsa.Encryption, message = TestMessages.Normal });

            var aesParameters = aesBody.GetProperty("parameters");
            var ecdhParameters = ecdhBody.GetProperty("parameters");
            var rsaParameters = rsaBody.GetProperty("parameters");

            Assert.Equal(12, Convert.FromBase64String(aesParameters.RequiredString("nonce")).Length);
            Assert.Equal(16, Convert.FromBase64String(aesParameters.RequiredString("authenticationTag")).Length);
            Assert.Equal(JsonValueKind.Null, aesParameters.GetProperty("ephemeralPublicKey").ValueKind);

            Assert.Equal(12, Convert.FromBase64String(ecdhParameters.RequiredString("nonce")).Length);
            Assert.Equal(16, Convert.FromBase64String(ecdhParameters.RequiredString("authenticationTag")).Length);
            Assert.False(string.IsNullOrWhiteSpace(ecdhParameters.RequiredString("ephemeralPublicKey")));

            // RSA-OAEP has no nonce, tag or ephemeral key, and must not pretend otherwise.
            Assert.Equal(JsonValueKind.Null, rsaParameters.GetProperty("nonce").ValueKind);
            Assert.Equal(JsonValueKind.Null, rsaParameters.GetProperty("authenticationTag").ValueKind);
            Assert.Equal(JsonValueKind.Null, rsaParameters.GetProperty("ephemeralPublicKey").ValueKind);
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task Encrypting_the_same_message_twice_gives_different_output(string method)
        {
            var keys = await GenerateAsync(method);

            var (_, first) = await _client.PostJsonAsync(
                $"/api/encrypt/{method}", new { key = keys.Encryption, message = TestMessages.Normal });
            var (_, second) = await _client.PostJsonAsync(
                $"/api/encrypt/{method}", new { key = keys.Encryption, message = TestMessages.Normal });

            Assert.False(
                string.Equals(
                    first.RequiredString("encryptedMessage"),
                    second.RequiredString("encryptedMessage"),
                    StringComparison.Ordinal),
                $"'{method}' produced identical output twice, which leaks that the messages are the same.");
        }

        [Theory]
        [InlineData("aes", "aesgcm")]
        [InlineData("aes", "AES-GCM")]
        [InlineData("rsa", "rsa-oaep")]
        [InlineData("ecc-hillman", "ecdh")]
        [InlineData("ecc-hillman", "ECCHillman")]
        public async Task An_alias_reaches_the_same_method_as_its_canonical_name(string method, string alias)
        {
            var keys = await GenerateAsync(method);

            var (_, encryptedBody) = await _client.PostJsonAsync(
                $"/api/encrypt/{alias}", new { key = keys.Encryption, message = TestMessages.Normal });

            var (decrypted, decryptedBody) = await _client.PostJsonAsync(
                $"/api/decrypt/{method}",
                new { key = keys.Decryption, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });

            Assert.Equal(HttpStatusCode.OK, decrypted.StatusCode);
            Assert.Equal(TestMessages.Normal, decryptedBody.GetProperty("message").GetString());
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task The_wrong_key_is_refused_without_repeating_the_key_or_the_message(string method)
        {
            var keys = await GenerateAsync(method);
            var other = await GenerateAsync(method);

            var (_, encryptedBody) = await _client.PostJsonAsync(
                $"/api/encrypt/{method}", new { key = keys.Encryption, message = TestMessages.Normal });

            var (response, body) = await _client.PostJsonAsync(
                $"/api/decrypt/{method}",
                new { key = other.Decryption, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });

            response.AssertProblem();
            ApiClient.AssertHidesSecrets(
                body,
                ("decryption key", other.Decryption),
                ("encryption key", keys.Encryption),
                ("plaintext", TestMessages.Normal));
        }

        [Theory]
        [MemberData(nameof(Methods))]
        public async Task An_altered_encrypted_message_is_refused(string method)
        {
            var keys = await GenerateAsync(method);

            var (_, encryptedBody) = await _client.PostJsonAsync(
                $"/api/encrypt/{method}", new { key = keys.Encryption, message = TestMessages.Normal });

            var tampered = EnvelopeEditor.FlipLastByte(encryptedBody.RequiredString("encryptedMessage"));

            var (response, _) = await _client.PostJsonAsync(
                $"/api/decrypt/{method}", new { key = keys.Decryption, encryptedMessage = tampered });

            response.AssertProblem();
        }

        [Fact]
        public async Task A_message_from_one_method_cannot_be_decrypted_by_another()
        {
            var aes = await GenerateAsync("aes");
            var ecdh = await GenerateAsync("ecc-hillman");

            var (_, encryptedBody) = await _client.PostJsonAsync(
                "/api/encrypt/aes", new { key = aes.Encryption, message = TestMessages.Normal });

            var (response, _) = await _client.PostJsonAsync(
                "/api/decrypt/ecc-hillman",
                new { key = ecdh.Decryption, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });
            var body = await response.Content.ReadAsStringAsync();

            response.AssertProblem();
            Assert.Contains("different encryption method", body, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_message_too_large_for_rsa_is_refused_with_a_usable_suggestion()
        {
            var keys = await GenerateAsync("rsa");

            var (response, _) = await _client.PostJsonAsync(
                "/api/encrypt/rsa", new { key = keys.Encryption, message = TestMessages.RsaOversizedFor2048 });
            var body = await response.Content.ReadAsStringAsync();

            response.AssertProblem();
            Assert.Contains("too large", body, StringComparison.Ordinal);
            Assert.Contains("ecc-hillman", body, StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_rsa_key_below_the_minimum_size_is_refused_by_the_encryption_endpoint()
        {
            // The generator still offers 512 bits for compatibility, but encryption must not accept it.
            var (_, generated) = await _client.PostJsonAsync("/api/keygen/rsa", new { keySize = 512 });

            var (response, _) = await _client.PostJsonAsync(
                "/api/encrypt/rsa",
                new { key = generated.RequiredString("publicKey"), message = TestMessages.Normal });
            var body = await response.Content.ReadAsStringAsync();

            response.AssertProblem();
            Assert.Contains("2048 bits", body, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("/api/encrypt/aes")]
        [InlineData("/api/decrypt/aes")]
        public async Task A_key_that_is_not_base64_is_refused(string route)
        {
            var (response, _) = await _client.PostJsonAsync(
                route,
                new { key = "not base64 !!", message = TestMessages.Normal, encryptedMessage = "AAAAAAAA" });
            var body = await response.Content.ReadAsStringAsync();

            response.AssertProblem();
            Assert.Contains("Base64", body, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("/api/encrypt/nope")]
        [InlineData("/api/decrypt/nope")]
        public async Task An_unsupported_method_is_refused_and_the_supported_ones_are_listed(string route)
        {
            var (response, body) = await _client.PostJsonAsync(
                route,
                new { key = TestKeys.Aes(), message = TestMessages.Normal, encryptedMessage = "AAAAAAAA" });

            response.AssertProblem();

            // Read from the parsed document: JSON escapes the quotes around the method name.
            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported method 'nope'", detail, StringComparison.Ordinal);
            Assert.Contains("aes-gcm", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_missing_key_is_reported_as_a_validation_error()
        {
            var (encrypt, _) = await _client.PostJsonAsync("/api/encrypt/aes", new { message = TestMessages.Normal });
            var (decrypt, _) = await _client.PostJsonAsync("/api/decrypt/aes", new { encryptedMessage = "AAAAAAAA" });

            encrypt.AssertProblem();
            decrypt.AssertProblem();
            Assert.Contains("A key is required.", await encrypt.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            Assert.Contains("A key is required.", await decrypt.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_missing_encrypted_message_is_reported_as_a_validation_error()
        {
            var (response, _) = await _client.PostJsonAsync("/api/decrypt/aes", new { key = TestKeys.Aes() });

            response.AssertProblem();
            Assert.Contains(
                "An encrypted message is required.",
                await response.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_body_that_is_not_json_is_refused_before_any_cryptography_runs()
        {
            var response = await _client.PostAsync(
                "/api/encrypt/aes",
                new StringContent("key=abc&message=hello", Encoding.UTF8, "text/plain"));

            Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/encrypt/aes",
                new StringContent("{\"key\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }

        [Fact]
        public async Task The_decrypt_response_carries_only_the_method_and_the_message()
        {
            var keys = await GenerateAsync("aes");

            var (_, encryptedBody) = await _client.PostJsonAsync(
                "/api/encrypt/aes", new { key = keys.Encryption, message = TestMessages.Normal });
            var (_, decryptedBody) = await _client.PostJsonAsync(
                "/api/decrypt/aes",
                new { key = keys.Decryption, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });

            Assert.Equal(
                new[] { "message", "method" },
                decryptedBody.EnumerateObject().Select(property => property.Name).Order().ToArray());
        }

        [Theory]
        [InlineData("/api/encrypt/methods")]
        [InlineData("/api/decrypt/methods")]
        public async Task The_discovery_endpoints_document_every_method(string route)
        {
            var (response, body) = await _client.GetJsonAsync(route);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(
                new[] { "aes-gcm", "ecc-hillman", "rsa-oaep" },
                body.EnumerateArray().Select(method => method.RequiredString("name")).ToArray());

            foreach (var method in body.EnumerateArray())
            {
                Assert.NotEmpty(method.GetProperty("aliases").EnumerateArray());
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("description")));
                Assert.False(string.IsNullOrWhiteSpace(method.RequiredString("keyFormat")));
                Assert.Contains("version(1)", method.RequiredString("envelopeLayout"), StringComparison.Ordinal);
            }
        }

        [Fact]
        public async Task A_long_message_survives_the_round_trip_over_http()
        {
            var keys = await GenerateAsync("ecc-hillman");

            var (_, encryptedBody) = await _client.PostJsonAsync(
                "/api/encrypt/ecc-hillman", new { key = keys.Encryption, message = TestMessages.Long });
            var (decrypted, decryptedBody) = await _client.PostJsonAsync(
                "/api/decrypt/ecc-hillman",
                new { key = keys.Decryption, encryptedMessage = encryptedBody.RequiredString("encryptedMessage") });

            Assert.Equal(HttpStatusCode.OK, decrypted.StatusCode);
            Assert.Equal(TestMessages.Long, decryptedBody.GetProperty("message").GetString());
        }

        /// <summary>Generates a key through the API and returns the halves each direction needs.</summary>
        private async Task<(string Encryption, string Decryption)> GenerateAsync(string method)
        {
            var (response, body) = await _client.PostJsonAsync($"/api/keygen/{method}", new { keySize = (int?)null });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            return body.TryGetProperty("key", out _)
                ? (body.RequiredString("key"), body.RequiredString("key"))
                : (body.RequiredString("publicKey"), body.RequiredString("privateKey"));
        }
    }
}
