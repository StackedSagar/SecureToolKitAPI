using System.Net;
using System.Text.Json;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The endpoints that are not cryptographic: the health probes that existed before this work, the
    /// generated OpenAPI document, and the framework behaviour callers rely on for wrong routes or verbs.
    /// </summary>
    [Collection(ApiCollection.Name)]
    public class HealthAndDocumentationTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        [Theory]
        [InlineData("/health")]
        [InlineData("/healthcheck")]
        public async Task Both_health_probes_still_answer(string route)
        {
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task The_openapi_document_describes_every_endpoint_group()
        {
            var (response, body) = await _client.GetJsonAsync("/swagger/v1/swagger.json");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var paths = body.GetProperty("paths");

            foreach (var path in new[]
                     {
                         "/api/KeyGen/methods",
                         "/api/KeyGen/{method}",
                         "/api/Encrypt/{method}",
                         "/api/Decrypt/{method}",
                         "/api/Signature/{method}/sign",
                         "/api/Signature/{method}/verify",
                         "/api/password",
                         "/api/password/bulk",
                         "/api/password/passphrase",
                         "/api/password/presets",
                         "/api/password/presets/{preset}",
                         "/api/developer/api-key",
                         "/api/developer/jwt-secret",
                         "/api/developer/oauth-token",
                         "/api/developer/ai-key",
                         "/api/developer/ai-key/providers",
                         "/api/developer/webauthn-credential",
                         "/api/developer/random-string",
                         "/api/developer/vapid-key",
                         "/api/encryption/encryption-key",
                         "/api/encryption/aes",
                         "/api/encryption/aes-256",
                         "/api/encryption/rsa",
                         "/api/encryption/hmac",
                         "/api/encryption/secret",
                         "/api/encryption/salt",
                         "/api/recovery/backup-codes",
                         "/api/recovery/recovery-key",
                         "/api/recovery/strength",
                         "/api/recovery/entropy",
                         "/api/identity/uuid",
                         "/api/identity/totp-secret",
                         "/api/identity/totp-authenticator",
                         "/api/identity/totp-code",
                         "/api/identity/base32",
                         "/api/identity/test-cards",
                         "/api/framework/django",
                         "/api/framework/flask",
                         "/api/framework/laravel",
                         "/api/framework/wordpress-salts",
                         "/api/network/ssh",
                         "/api/network/ssh/key-types",
                         "/api/hash",
                         "/api/hash/sha256",
                         "/api/hash/md5",
                         "/api/hash/algorithms"
                     })
            {
                Assert.True(paths.TryGetProperty(path, out _), $"The OpenAPI document is missing '{path}'.");
            }
        }

        [Fact]
        public async Task The_openapi_document_carries_the_xml_documentation()
        {
            var (_, body) = await _client.GetJsonAsync("/swagger/v1/swagger.json");

            var encrypt = body.GetProperty("paths").GetProperty("/api/Encrypt/{method}").GetProperty("post");

            // The summaries come from the XML comments, so an empty summary means the documentation file
            // was not published alongside the assembly.
            Assert.False(string.IsNullOrWhiteSpace(encrypt.GetProperty("summary").GetString()));
        }

        [Theory]
        [InlineData("/api/does-not-exist")]
        [InlineData("/api/keygen/aes/extra-segment")]
        public async Task An_unknown_route_is_a_not_found_rather_than_an_error(string route)
        {
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Fact]
        public async Task The_wrong_verb_is_reported_as_method_not_allowed()
        {
            // Only POST is mapped for /api/encrypt/{method}, so a GET matches the route but not the verb.
            var response = await _client.GetAsync("/api/encrypt/aes");

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task No_endpoint_leaks_key_material_into_the_method_listings()
        {
            foreach (var route in new[]
                     {
                         "/api/keygen/methods",
                         "/api/encrypt/methods",
                         "/api/decrypt/methods",
                         "/api/signature/methods"
                     })
            {
                var (response, body) = await _client.GetJsonAsync(route);

                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal(JsonValueKind.Array, body.ValueKind);

                foreach (var method in body.EnumerateArray())
                {
                    Assert.False(method.TryGetProperty("key", out _));
                    Assert.False(method.TryGetProperty("privateKey", out _));
                }
            }
        }
    }
}
