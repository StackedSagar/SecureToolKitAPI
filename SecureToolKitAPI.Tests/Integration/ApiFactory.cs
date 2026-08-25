using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// Hosts the real API in memory, with the real dependency injection wiring, so the integration tests
    /// exercise the same pipeline a caller would reach.
    /// </summary>
    /// <remarks>
    /// The development environment is selected so the generated OpenAPI document is served and can be checked.
    /// </remarks>
    public sealed class ApiFactory : WebApplicationFactory<Program>
    {
        /// <inheritdoc />
        protected override void ConfigureWebHost(IWebHostBuilder builder) => builder.UseEnvironment("Development");
    }

    /// <summary>Shares one hosted API across the integration test classes instead of starting one per class.</summary>
    [CollectionDefinition(ApiCollection.Name)]
    public sealed class ApiCollection : ICollectionFixture<ApiFactory>
    {
        /// <summary>The collection name the integration test classes join.</summary>
        public const string Name = "API";
    }

    /// <summary>Request and response helpers shared by the integration tests.</summary>
    internal static class ApiClient
    {
        /// <summary>Sends a JSON body and returns the response together with its parsed body.</summary>
        internal static async Task<(HttpResponseMessage Response, JsonElement Body)> PostJsonAsync(
            this HttpClient client,
            string requestUri,
            object payload)
        {
            var response = await client.PostAsJsonAsync(requestUri, payload);

            return (response, await ReadJsonAsync(response));
        }

        /// <summary>Sends a GET request and returns the response together with its parsed body.</summary>
        internal static async Task<(HttpResponseMessage Response, JsonElement Body)> GetJsonAsync(
            this HttpClient client,
            string requestUri)
        {
            var response = await client.GetAsync(requestUri);

            return (response, await ReadJsonAsync(response));
        }

        /// <summary>Reads a JSON response body into a value that stays usable after the document is disposed.</summary>
        internal static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
        {
            var text = await response.Content.ReadAsStringAsync();

            Assert.False(string.IsNullOrWhiteSpace(text), "The response body was empty.");

            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }

        /// <summary>Reads a required string property, failing the test when it is missing or blank.</summary>
        internal static string RequiredString(this JsonElement body, string propertyName)
        {
            Assert.True(
                body.TryGetProperty(propertyName, out var property),
                $"The response did not contain the '{propertyName}' property, which callers depend on.");

            var value = property.GetString();

            Assert.False(string.IsNullOrEmpty(value), $"The '{propertyName}' property was empty.");
            return value!;
        }

        /// <summary>Asserts the response is a JSON problem document with the expected status.</summary>
        internal static void AssertProblem(this HttpResponseMessage response, HttpStatusCode expected = HttpStatusCode.BadRequest)
        {
            Assert.Equal(expected, response.StatusCode);

            // RFC 9457 responses may be served as application/problem+json or application/json depending on
            // content negotiation, so only the JSON part is asserted here.
            Assert.Contains(
                "json",
                response.Content.Headers.ContentType?.MediaType ?? string.Empty,
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Asserts a response carries none of the sensitive values from the request. The parsed body is
        /// searched rather than the raw text, because JSON escapes some characters that Base64 keys
        /// contain, which would let a leaked value slip past a plain text search. Failures print the
        /// label rather than the value, so secrets never reach the test log.
        /// </summary>
        internal static void AssertHidesSecrets(JsonElement body, params (string Label, string Value)[] secrets)
        {
            var text = string.Join("\n", Strings(body));

            foreach (var (label, value) in secrets)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                Assert.False(
                    text.Contains(value, StringComparison.Ordinal),
                    $"The response echoed the {label} back to the caller.");
            }
        }

        /// <summary>Every string in a JSON document, decoded, including the property names.</summary>
        private static IEnumerable<string> Strings(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        yield return property.Name;

                        foreach (var value in Strings(property.Value))
                        {
                            yield return value;
                        }
                    }

                    break;

                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        foreach (var value in Strings(item))
                        {
                            yield return value;
                        }
                    }

                    break;

                case JsonValueKind.String:
                    yield return element.GetString() ?? string.Empty;
                    break;

                default:
                    yield return element.ToString();
                    break;
            }
        }
    }
}
