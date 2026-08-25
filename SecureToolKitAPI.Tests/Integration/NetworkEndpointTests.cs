using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The SSH key endpoints over HTTP: that the generation route answers with a usable key pair, that the
    /// options in the body are applied, that the catalogue lists what the generator will produce, and that
    /// unusable options and wrong verbs become problem responses rather than exceptions or surprises.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The private key is the one secret this API deliberately returns, so it cannot be asserted absent the
    /// way other endpoints' secrets are. Instead the tests check its shape without printing it, and confirm no
    /// field that is meant to be publishable — the public key, the fingerprint, the description — carries any
    /// of it.
    /// </para>
    /// <para>
    /// Generation is POST because the response body carries a private key and a URL ends up in server logs,
    /// proxy logs and browser history. The catalogue is GET because it is fixed and public. Two wrong-verb
    /// tests keep both that way. Two more assert that PGP and WireGuard are absent, so the decision to leave
    /// them out stays visible rather than looking like an accident.
    /// </para>
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class NetworkEndpointTests(ApiFactory factory)
    {
        /// <summary>The PEM label an unencrypted PKCS#8 private key opens with.</summary>
        private const string PemHeader = "-----BEGIN PRIVATE KEY-----";

        private readonly HttpClient _client = factory.CreateClient();

        [Fact]
        public async Task The_ssh_route_answers_without_a_body_with_an_rsa_key_pair()
        {
            var response = await _client.PostAsync("/api/network/ssh", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("rsa", body.RequiredString("algorithm"));
            Assert.Equal("ssh-rsa", body.RequiredString("keyType"));
            Assert.Equal(3072, body.GetProperty("bits").GetInt32());
            Assert.Equal(128, body.GetProperty("securityStrengthBits").GetInt32());

            // The public key is one authorized_keys line: the key type, then the Base64 blob, and no comment
            // when none was asked for.
            var publicKey = body.RequiredString("publicKey");

            Assert.StartsWith("ssh-rsa ", publicKey, StringComparison.Ordinal);
            Assert.Equal(2, publicKey.Split(' ').Length);

            Assert.NotEmpty(body.GetProperty("warnings").EnumerateArray());
            Assert.False(
                body.TryGetProperty("comment", out _),
                "The response carried a comment property when no comment was asked for.");
        }

        [Fact]
        public async Task The_ssh_response_carries_an_unencrypted_pkcs8_private_key()
        {
            var response = await _client.PostAsync("/api/network/ssh", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            var privateKey = body.RequiredString("privateKey");

            // The header is checked but the body is never asserted against anything, so no key material
            // reaches the log.
            Assert.StartsWith(PemHeader, privateKey.TrimStart(), StringComparison.Ordinal);
            Assert.Equal("Unencrypted PKCS#8 private key in PEM.", body.RequiredString("privateKeyFormat"));
        }

        [Fact]
        public async Task The_fingerprint_is_a_sha256_openssh_fingerprint()
        {
            var response = await _client.PostAsync("/api/network/ssh", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            var fingerprint = body.RequiredString("fingerprint");

            // "SHA256:" and 43 unpadded Base64 characters over a 32-byte digest. The fingerprint is a hash of
            // a public value, so it is safe to compare and safe to print.
            Assert.StartsWith("SHA256:", fingerprint, StringComparison.Ordinal);
            Assert.Equal(50, fingerprint.Length);
            Assert.False(
                fingerprint.Contains('=', StringComparison.Ordinal),
                "The fingerprint carried Base64 padding, which ssh-keygen does not print.");
        }

        [Theory]
        [InlineData("ecdsa", 256, "ecdsa-sha2-nistp256", 128)]
        [InlineData("ecdsa", 384, "ecdsa-sha2-nistp384", 192)]
        [InlineData("ecdsa", 521, "ecdsa-sha2-nistp521", 256)]
        [InlineData("rsa", 2048, "ssh-rsa", 112)]
        [InlineData("rsa", 4096, "ssh-rsa", 128)]
        public async Task The_requested_algorithm_and_size_are_applied(
            string algorithm,
            int bits,
            string expectedKeyType,
            int expectedStrength)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { algorithm, bits });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(algorithm, body.RequiredString("algorithm"));
            Assert.Equal(bits, body.GetProperty("bits").GetInt32());
            Assert.Equal(expectedKeyType, body.RequiredString("keyType"));
            Assert.Equal(expectedStrength, body.GetProperty("securityStrengthBits").GetInt32());
            Assert.StartsWith($"{expectedKeyType} ", body.RequiredString("publicKey"), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("RSA")]
        [InlineData("Rsa")]
        [InlineData("ec-dsa")]
        [InlineData("ECDSA")]
        public async Task The_algorithm_name_is_matched_without_regard_to_case_or_separators(string algorithm)
        {
            var (response, _) = await _client.PostJsonAsync("/api/network/ssh", new { algorithm });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task A_comment_is_appended_to_the_public_key_line_and_reported_back()
        {
            const string comment = "deploy@build-agent";

            var (response, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { algorithm = "ecdsa", comment });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(comment, body.RequiredString("comment"));

            var parts = body.RequiredString("publicKey").Split(' ');

            Assert.Equal(3, parts.Length);
            Assert.Equal(comment, parts[2]);
        }

        [Fact]
        public async Task A_comment_carrying_a_newline_is_a_bad_request()
        {
            // A newline in the comment would close the authorized_keys line and let whatever followed be read
            // as a second authorized key, so the API must refuse it rather than write it out.
            var (response, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { comment = "deploy\nssh-rsa AAAAinjected" });

            response.AssertProblem();
            Assert.Contains("printable ASCII", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task Ed25519_is_reported_as_unsupported_rather_than_quietly_substituted()
        {
            // ed25519 is the key type OpenSSH prefers, so a caller might reasonably ask for it. Handing back an
            // RSA key instead would be worse than saying no, so the API says no.
            var (response, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { algorithm = "ed25519" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported key algorithm", detail, StringComparison.Ordinal);
            Assert.Contains("Rsa", detail, StringComparison.Ordinal);
            Assert.Contains("Ecdsa", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("rsa", 1024)]
        [InlineData("rsa", 512)]
        [InlineData("ecdsa", 512)]
        [InlineData("ecdsa", 255)]
        public async Task A_key_size_the_api_does_not_support_is_a_bad_request(string algorithm, int bits)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { algorithm, bits });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Supported sizes are:", detail, StringComparison.Ordinal);
            Assert.Contains(algorithm, detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_key_types_route_lists_every_combination_the_generator_produces()
        {
            var (response, body) = await _client.GetJsonAsync("/api/network/ssh/key-types");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var entries = body.EnumerateArray().ToArray();

            Assert.Equal(6, entries.Length);
            Assert.Equal(
                new[] { "rsa", "rsa", "rsa", "ecdsa", "ecdsa", "ecdsa" },
                entries.Select(entry => entry.RequiredString("algorithm")).ToArray());
            Assert.Equal(
                new[] { 2048, 3072, 4096, 256, 384, 521 },
                entries.Select(entry => entry.GetProperty("bits").GetInt32()).ToArray());

            var defaults = entries.Where(entry => entry.GetProperty("isDefault").GetBoolean()).ToArray();

            Assert.Single(defaults);
            Assert.Equal("rsa", defaults[0].RequiredString("algorithm"));
            Assert.Equal(3072, defaults[0].GetProperty("bits").GetInt32());
            Assert.All(entries, entry => Assert.False(
                string.IsNullOrWhiteSpace(entry.RequiredString("notes")),
                "A catalogue entry had no notes."));
        }

        [Fact]
        public async Task A_key_type_the_catalogue_advertises_can_actually_be_generated()
        {
            // The catalogue's promise is only good if a caller can send back what it lists and get a key, so
            // this walks the listing and generates each entry.
            var (_, catalogue) = await _client.GetJsonAsync("/api/network/ssh/key-types");

            foreach (var entry in catalogue.EnumerateArray())
            {
                var algorithm = entry.RequiredString("algorithm");
                var bits = entry.GetProperty("bits").GetInt32();

                var (response, body) = await _client.PostJsonAsync(
                    "/api/network/ssh",
                    new { algorithm, bits });

                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal(entry.RequiredString("keyType"), body.RequiredString("keyType"));
                Assert.Equal(
                    entry.GetProperty("securityStrengthBits").GetInt32(),
                    body.GetProperty("securityStrengthBits").GetInt32());
            }
        }

        [Fact]
        public async Task Two_calls_never_return_the_same_key()
        {
            var fingerprints = new List<string>();

            for (var attempt = 0; attempt < 5; attempt++)
            {
                var (_, body) = await _client.PostJsonAsync("/api/network/ssh", new { algorithm = "ecdsa" });
                fingerprints.Add(body.RequiredString("fingerprint"));
            }

            // Fingerprints identify a key uniquely and are public, so comparing them leaks nothing.
            Assert.Equal(fingerprints.Count, fingerprints.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public async Task No_publishable_field_carries_the_private_key()
        {
            var (_, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { algorithm = "rsa", bits = 2048 });

            var privateKey = body.RequiredString("privateKey");
            var privateBody = string.Concat(
                privateKey
                    .Split('\n')
                    .Select(line => line.Trim())
                    .Where(line => line.Length > 0 && !line.StartsWith("-----", StringComparison.Ordinal)));

            // A chunk from the second half of the PKCS#8 body, where the private exponent and primes live, so
            // a match cannot be the modulus that legitimately appears in both halves of the key pair.
            var chunk = privateBody.Substring(privateBody.Length / 2, 32);

            foreach (var field in new[] { "publicKey", "fingerprint", "composition", "keyType" })
            {
                Assert.False(
                    body.RequiredString(field).Contains(chunk, StringComparison.Ordinal),
                    $"The {field} field, which is publishable, contained part of the private key.");
            }

            Assert.All(
                body.GetProperty("warnings").EnumerateArray(),
                warning => Assert.False(
                    (warning.GetString() ?? string.Empty).Contains(chunk, StringComparison.Ordinal),
                    "An advisory contained part of the private key."));
        }

        [Fact]
        public async Task A_get_on_the_generation_route_is_not_allowed()
        {
            // A GET would put the request in a URL and return a private key against it, which is the shape
            // this route exists to avoid.
            var response = await _client.GetAsync("/api/network/ssh");

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task A_post_to_the_key_types_route_is_not_allowed()
        {
            // The catalogue is a fixed public listing, so it is a GET; posting to it is a client mistake worth
            // reporting rather than silently accepting.
            var response = await _client.PostAsync("/api/network/ssh/key-types", content: null);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Theory]
        [InlineData("/api/network/pgp")]
        [InlineData("/api/network/wireguard")]
        public async Task The_omitted_network_key_types_are_absent_rather_than_half_built(string route)
        {
            // PGP and WireGuard are deliberately not implemented: a PGP key is an OpenPGP packet-format problem
            // and WireGuard needs X25519, which .NET does not expose. This test pins that they return nothing
            // rather than a stub, so a later half-implementation would fail here first.
            var response = await _client.PostAsync(route, content: null);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Fact]
        public async Task A_rejected_request_is_explained_without_exposing_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/network/ssh",
                new { algorithm = "rsa", bits = 999999 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("Exception", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SecureToolKitAPI", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/network/ssh",
                new StringContent("{\"bits\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }
    }
}
