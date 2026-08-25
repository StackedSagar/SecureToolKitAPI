using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The hashing endpoints end to end: that a digest computed over HTTP is the digest the standard defines,
    /// that the route-fixed variants agree with the general route, that a bad request comes back as a problem
    /// document rather than a framework failure, and that the message never appears in the response.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The digests asserted here are known-answer vectors from FIPS 180-4 and RFC 1321, the same ones the unit
    /// tests use. Repeating them at this level is deliberate: the unit tests prove the generator computes them,
    /// and these prove the JSON contract, the option parsing and the routing deliver them unchanged to a
    /// caller.
    /// </para>
    /// <para>
    /// Nothing here is secret. Digests and the messages that produced them are literals from a specification,
    /// so values may appear in failure output; the one thing that must not appear is a caller's message in a
    /// response, which is asserted directly.
    /// </para>
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class HashEndpointTests(ApiFactory factory)
    {
        /// <summary>The SHA-256 digest of <c>abc</c>, from FIPS 180-4.</summary>
        private const string Sha256Abc =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        /// <summary>The MD5 digest of <c>abc</c>, from RFC 1321.</summary>
        private const string Md5Abc = "900150983cd24fb0d6963f7d28e17f72";

        /// <summary>The SHA-256 digest of the empty message, from FIPS 180-4.</summary>
        private const string Sha256Empty =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>The routes that compute a digest, each of which requires a message.</summary>
        public static TheoryData<string> HashRoutes => new()
        {
            "/api/hash",
            "/api/hash/sha256",
            "/api/hash/md5"
        };

        [Fact]
        public async Task The_general_route_defaults_to_sha256()
        {
            var (response, body) = await _client.PostJsonAsync("/api/hash", new { message = "abc" });

            response.EnsureSuccessStatusCode();

            Assert.Equal("SHA-256", body.RequiredString("algorithm"));
            Assert.Equal(Sha256Abc, body.RequiredString("digest"));
            Assert.Equal(256, body.GetProperty("digestSizeBits").GetInt32());
            Assert.Equal(3, body.GetProperty("inputByteCount").GetInt32());
            Assert.False(body.GetProperty("isCryptographicallyBroken").GetBoolean());
            Assert.Equal("lowercase hexadecimal", body.RequiredString("encoding"));
            Assert.Equal("UTF-8 text", body.RequiredString("inputFormat"));
        }

        [Theory]
        [InlineData("sha256", "SHA-256", Sha256Abc)]
        [InlineData("SHA-256", "SHA-256", Sha256Abc)]
        [InlineData("sha_256", "SHA-256", Sha256Abc)]
        [InlineData(
            "sha384",
            "SHA-384",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")]
        [InlineData(
            "sha512",
            "SHA-512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
            + "454d4423643ce80e2a9ac94fa54ca49f")]
        [InlineData("md5", "MD5", Md5Abc)]
        [InlineData("MD-5", "MD5", Md5Abc)]
        public async Task The_named_function_is_the_one_that_computes_the_digest(
            string requested,
            string expectedName,
            string expectedDigest)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { algorithm = requested, message = "abc" });

            response.EnsureSuccessStatusCode();

            Assert.Equal(expectedName, body.RequiredString("algorithm"));
            Assert.Equal(expectedDigest, body.RequiredString("digest"));
        }

        [Fact]
        public async Task The_sha256_route_computes_sha256_without_being_asked()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash/sha256",
                new { message = "abc" });

            response.EnsureSuccessStatusCode();

            Assert.Equal("SHA-256", body.RequiredString("algorithm"));
            Assert.Equal(Sha256Abc, body.RequiredString("digest"));
        }

        [Fact]
        public async Task The_md5_route_computes_md5_and_says_it_is_broken()
        {
            var (response, body) = await _client.PostJsonAsync("/api/hash/md5", new { message = "abc" });

            response.EnsureSuccessStatusCode();

            Assert.Equal("MD5", body.RequiredString("algorithm"));
            Assert.Equal(Md5Abc, body.RequiredString("digest"));
            Assert.Equal(128, body.GetProperty("digestSizeBits").GetInt32());

            // The flag is what a caller can act on in code; the warning is what a person reads.
            Assert.True(body.GetProperty("isCryptographicallyBroken").GetBoolean());

            var warnings = Warnings(body);

            Assert.Contains(
                warnings,
                warning => warning.Contains("MD5 is cryptographically broken", StringComparison.Ordinal));
            Assert.Contains(
                warnings,
                warning => warning.Contains("Prefer SHA-256", StringComparison.Ordinal));
        }

        [Fact]
        public async Task A_route_that_fixes_the_function_agrees_with_naming_it_on_the_general_route()
        {
            // Two ways of asking for the same thing must not drift apart, so the whole response is compared
            // rather than only the digest.
            var (_, viaRoute) = await _client.PostJsonAsync("/api/hash/md5", new { message = "hello world" });
            var (_, viaName) = await _client.PostJsonAsync(
                "/api/hash",
                new { algorithm = "md5", message = "hello world" });

            Assert.Equal(viaName.RequiredString("digest"), viaRoute.RequiredString("digest"));
            Assert.Equal(viaName.RequiredString("algorithm"), viaRoute.RequiredString("algorithm"));
            Assert.Equal(viaName.RequiredString("composition"), viaRoute.RequiredString("composition"));
            Assert.Equal(Warnings(viaName), Warnings(viaRoute));
        }

        [Fact]
        public async Task An_algorithm_sent_to_a_route_that_fixes_one_does_not_change_the_function()
        {
            // The extra property is ignored rather than honoured. If it were honoured, /api/hash/sha256 could
            // return an MD5 digest, and a caller who trusted the URL would be wrong about what they held.
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash/sha256",
                new { algorithm = "md5", message = "abc" });

            response.EnsureSuccessStatusCode();

            Assert.Equal("SHA-256", body.RequiredString("algorithm"));
            Assert.Equal(Sha256Abc, body.RequiredString("digest"));
            Assert.False(body.GetProperty("isCryptographicallyBroken").GetBoolean());
        }

        [Theory]
        [InlineData("hex", Sha256Abc)]
        [InlineData("hexupper", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
        [InlineData("base64", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")]
        public async Task The_digest_is_written_the_way_the_caller_asked(string encoding, string expected)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { encoding, message = "abc" });

            response.EnsureSuccessStatusCode();

            Assert.Equal(expected, body.RequiredString("digest"));

            // The size is a property of the function and must not follow the rendering.
            Assert.Equal(256, body.GetProperty("digestSizeBits").GetInt32());
        }

        [Fact]
        public async Task Bytes_can_be_sent_as_base64_so_a_file_checksum_can_be_reproduced()
        {
            // 00 ff 10 80 7f — bytes that no text encoding would carry intact, which is the case this option
            // exists for.
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash/md5",
                new { inputFormat = "base64", message = "AP8QgH8=" });

            response.EnsureSuccessStatusCode();

            Assert.Equal("600d8b975d8f8e643bd18673ef904436", body.RequiredString("digest"));
            Assert.Equal(5, body.GetProperty("inputByteCount").GetInt32());
            Assert.Equal("Base64 decoded input", body.RequiredString("inputFormat"));
        }

        [Fact]
        public async Task The_same_bytes_hash_the_same_however_they_were_written_on_the_wire()
        {
            var (_, viaBase64) = await _client.PostJsonAsync(
                "/api/hash",
                new { inputFormat = "base64", message = "AP8QgH8=" });

            var (_, viaHex) = await _client.PostJsonAsync(
                "/api/hash",
                new { inputFormat = "hex", message = "00ff10807f" });

            Assert.Equal(viaBase64.RequiredString("digest"), viaHex.RequiredString("digest"));
            Assert.Equal(
                viaBase64.GetProperty("inputByteCount").GetInt32(),
                viaHex.GetProperty("inputByteCount").GetInt32());
        }

        [Fact]
        public async Task Text_is_hashed_as_utf8_across_the_wire()
        {
            // "caf" and e-acute, sent as JSON. The digest is the one for the UTF-8 bytes 63 61 66 c3 a9, so a
            // mismatch would mean the pipeline re-encoded the message somewhere between the body and the hash.
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { message = "caf" + (char)0x00E9 });

            response.EnsureSuccessStatusCode();

            Assert.Equal(
                "850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e",
                body.RequiredString("digest"));
            Assert.Equal(5, body.GetProperty("inputByteCount").GetInt32());
        }

        [Theory]
        [MemberData(nameof(HashRoutes))]
        public async Task An_empty_message_is_hashed_rather_than_refused(string route)
        {
            var (response, body) = await _client.PostJsonAsync(route, new { message = string.Empty });

            response.EnsureSuccessStatusCode();

            Assert.Equal(0, body.GetProperty("inputByteCount").GetInt32());
            Assert.False(string.IsNullOrEmpty(body.RequiredString("digest")));
        }

        [Fact]
        public async Task The_empty_message_gives_the_digest_the_standard_publishes()
        {
            var (response, body) = await _client.PostJsonAsync("/api/hash/sha256", new { message = "" });

            response.EnsureSuccessStatusCode();

            Assert.Equal(Sha256Empty, body.RequiredString("digest"));
        }

        [Theory]
        [MemberData(nameof(HashRoutes))]
        public async Task A_missing_message_is_this_apis_own_problem_response(string route)
        {
            var (response, body) = await _client.PostJsonAsync(route, new { encoding = "hex" });

            response.AssertProblem();

            Assert.Equal("Invalid cryptographic request.", body.RequiredString("title"));
            Assert.Equal("The message is required.", body.RequiredString("detail"));
            Assert.Equal(route, body.RequiredString("instance"));
        }

        [Theory]
        [MemberData(nameof(HashRoutes))]
        public async Task An_omitted_body_is_reported_as_a_missing_message_rather_than_a_binding_failure(
            string route)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            response.AssertProblem();

            // The point of allowing an empty body is that the caller is told what this API needs, in this
            // API's words, instead of being handed a model-binding error about a missing request body.
            Assert.Equal("The message is required.", body.RequiredString("detail"));
        }

        [Theory]
        [InlineData("sha1")]
        [InlineData("sha3-256")]
        [InlineData("bcrypt")]
        [InlineData("argon2")]
        [InlineData("crc32")]
        public async Task A_function_this_api_does_not_offer_is_refused_rather_than_substituted(
            string algorithm)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { algorithm, message = "abc" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported hash algorithm", detail, StringComparison.Ordinal);

            // The message lists what is available, so a caller can correct the request without reading the
            // documentation.
            Assert.Contains("Sha256", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unsupported_input_format_is_refused()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { inputFormat = "utf16", message = "abc" });

            response.AssertProblem();
            Assert.Contains(
                "Unsupported input format",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unsupported_digest_encoding_is_refused()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { encoding = "base58", message = "abc" });

            response.AssertProblem();
            Assert.Contains(
                "Unsupported digest encoding",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_message_that_is_not_the_format_it_claims_to_be_is_refused_without_being_echoed()
        {
            const string message = "this is not base64 and is also a secret";

            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { inputFormat = "base64", message });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("not valid Base64", detail, StringComparison.Ordinal);

            // A validation error that quoted the malformed value back would put the caller's data in whatever
            // logs the error reaches.
            ApiClient.AssertHidesSecrets(body, ("message", message));
        }

        [Fact]
        public async Task Hexadecimal_with_an_odd_number_of_digits_is_named_as_such()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { inputFormat = "hex", message = "00ff10807" });

            response.AssertProblem();
            Assert.Contains(
                "odd number of digits",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_message_beyond_the_size_limit_is_refused_rather_than_hashed()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/hash",
                new { message = new string('a', 4_194_305) });

            response.AssertProblem();
            Assert.Contains(
                "characters or fewer",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_message_is_never_echoed_back_in_a_successful_response()
        {
            // The message may be exactly the thing the caller is trying not to expose — they are fingerprinting
            // it, after all — so it is counted and dropped.
            const string message = "correct-horse-battery-staple-do-not-echo-this";

            var (response, body) = await _client.PostJsonAsync("/api/hash", new { message });

            response.EnsureSuccessStatusCode();

            ApiClient.AssertHidesSecrets(body, ("message", message));
            Assert.Equal(message.Length, body.GetProperty("inputByteCount").GetInt32());
        }

        [Theory]
        [MemberData(nameof(HashRoutes))]
        public async Task Every_response_says_that_hashing_is_not_encryption(string route)
        {
            var (response, body) = await _client.PostJsonAsync(route, new { message = "hello world" });

            response.EnsureSuccessStatusCode();

            var warnings = Warnings(body);

            Assert.Contains(
                warnings,
                warning => warning.Contains("A hash is not encryption.", StringComparison.Ordinal));
            Assert.Contains(
                warnings,
                warning => warning.Contains("Never store a password", StringComparison.Ordinal));
            Assert.Contains(
                warnings,
                warning => warning.Contains("does not show who produced it", StringComparison.Ordinal));
        }

        [Fact]
        public async Task The_algorithms_route_lists_the_supported_functions_strongest_first()
        {
            var (response, body) = await _client.GetJsonAsync("/api/hash/algorithms");

            response.EnsureSuccessStatusCode();

            var entries = body.EnumerateArray().ToArray();

            Assert.Equal(4, entries.Length);
            Assert.Equal(
                new[] { "SHA-512", "SHA-384", "SHA-256", "MD5" },
                entries.Select(entry => entry.RequiredString("algorithm")).ToArray());
            Assert.Equal(
                new[] { 512, 384, 256, 128 },
                entries.Select(entry => entry.GetProperty("digestSizeBits").GetInt32()).ToArray());

            var defaults = entries.Where(entry => entry.GetProperty("isDefault").GetBoolean()).ToArray();

            Assert.Single(defaults);
            Assert.Equal("SHA-256", defaults[0].RequiredString("algorithm"));

            var broken = entries
                .Where(entry => entry.GetProperty("isCryptographicallyBroken").GetBoolean())
                .ToArray();

            Assert.Single(broken);
            Assert.Equal("MD5", broken[0].RequiredString("algorithm"));

            Assert.All(entries, entry => Assert.False(
                string.IsNullOrWhiteSpace(entry.RequiredString("notes")),
                "A catalogue entry had no notes."));
        }

        [Fact]
        public async Task Every_advertised_function_can_actually_be_asked_for_by_the_name_advertised()
        {
            // A catalogue that named a function this API would then reject would send a caller down a path
            // that fails on the next request.
            var (_, catalogue) = await _client.GetJsonAsync("/api/hash/algorithms");

            foreach (var entry in catalogue.EnumerateArray())
            {
                var name = entry.RequiredString("algorithm");

                var (response, body) = await _client.PostJsonAsync(
                    "/api/hash",
                    new { algorithm = name, message = "abc" });

                response.EnsureSuccessStatusCode();

                Assert.Equal(name, body.RequiredString("algorithm"));
                Assert.Equal(
                    entry.GetProperty("digestSizeBits").GetInt32(),
                    body.GetProperty("digestSizeBits").GetInt32());
                Assert.Equal(
                    entry.GetProperty("isCryptographicallyBroken").GetBoolean(),
                    body.GetProperty("isCryptographicallyBroken").GetBoolean());
            }
        }

        [Fact]
        public async Task The_password_hashing_functions_are_absent_rather_than_half_built()
        {
            // bcrypt belongs to the plan's list for this controller but is deliberately not implemented: it is
            // not in the BCL, and a route that existed but computed something else would be worse than none.
            foreach (var route in new[] { "/api/hash/bcrypt", "/api/hash/argon2", "/api/hash/sha1" })
            {
                var response = await _client.PostAsync(route, content: null);

                Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            }
        }

        [Fact]
        public async Task A_get_on_a_hashing_route_is_not_allowed()
        {
            // The message travels in the body precisely so it stays out of URLs, server logs and browser
            // history, so there is no GET form of it.
            var response = await _client.GetAsync("/api/hash");

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task A_post_to_the_algorithms_route_is_not_allowed()
        {
            var response = await _client.PostAsync("/api/hash/algorithms", content: null);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            using var content = new StringContent("{\"message\":", Encoding.UTF8, "application/json");

            var response = await _client.PostAsync("/api/hash", content);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        /// <summary>Reads the advisories from a response body.</summary>
        /// <param name="body">The parsed response.</param>
        private static string[] Warnings(JsonElement body) =>
        [
            .. body.GetProperty("warnings").EnumerateArray().Select(warning => warning.GetString() ?? string.Empty)
        ];
    }
}
