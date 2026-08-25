using SecureToolKitAPI.Application;
using SecureToolKitAPI.Contracts.Developer;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates the secrets a developer wires into a service: API keys, JWT signing secrets, opaque OAuth
    /// values, AI provider shaped keys, the random values a WebAuthn registration needs, random strings and
    /// Web Push VAPID keys. Generation lives in <see cref="IDeveloperSecretGenerator"/>; this controller
    /// maps the request, resolves a named provider and maps the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These endpoints use POST with an optional body. No option and no generated value is taken from or
    /// placed in the URL, so nothing sensitive reaches a server or proxy access log.
    /// </para>
    /// <para>
    /// Every response except the provider listing contains secret material. Callers must treat it as
    /// sensitive: it is not logged here, and it should not be logged, cached or committed downstream.
    /// </para>
    /// <para>
    /// These values are machine credentials, so they are held to a higher bar than a human password: the
    /// generator attaches an advisory below 128 bits rather than below 60.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/developer")]
    [Produces("application/json")]
    public class DeveloperGeneratorController(IDeveloperSecretGenerator secrets) : ControllerBase
    {
        /// <summary>
        /// Generates an API key: random bytes rendered as text, optionally behind a recognisable prefix.
        /// </summary>
        /// <param name="request">
        /// Size, encoding and prefix. Omit the body for the default: 32 random bytes, or 256 bits, rendered
        /// as Base64url with no prefix.
        /// </param>
        /// <returns>Returns the key with the entropy it carries and how it was composed.</returns>
        /// <remarks>
        /// A prefix costs nothing and pays for itself: it lets a secret scanner recognise the key if it is
        /// ever committed or pasted somewhere public, and it tells support which environment a key belongs
        /// to. It adds no entropy and is reported separately for that reason.
        /// </remarks>
        [HttpPost("api-key")]
        [ProducesResponseType<DeveloperSecretResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateApiKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] ApiKeyRequest? request = null) =>
            Ok(ToResponse(secrets.GenerateApiKey(ToSpec(request))));

        /// <summary>
        /// Generates a symmetric secret for signing JSON Web Tokens, sized for the chosen HMAC algorithm.
        /// </summary>
        /// <param name="request">
        /// Algorithm and encoding. Omit the body for the default: a 256-bit HS256 secret, Base64 encoded.
        /// </param>
        /// <returns>Returns the secret, the algorithm it is sized for, and how it must be handled.</returns>
        /// <remarks>
        /// The size is not a caller option. RFC 7518 requires an HMAC key at least as long as the hash
        /// output, and a longer key adds no strength, so the algorithm settles it.
        /// </remarks>
        [HttpPost("jwt-secret")]
        [ProducesResponseType<DeveloperSecretResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateJwtSecret(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] JwtSecretRequest? request = null) =>
            Ok(ToResponse(secrets.GenerateJwtSecret(ToSpec(request))));

        /// <summary>
        /// Generates an opaque OAuth 2.0 value: an access token, refresh token, client secret or
        /// authorization code.
        /// </summary>
        /// <param name="request">
        /// Kind, size and encoding. Omit the body for the default: a 256-bit access token, Base64url
        /// encoded.
        /// </param>
        /// <returns>Returns the value with the advisories that belong to that kind of credential.</returns>
        /// <remarks>
        /// These are opaque tokens: random values with no structure, which a server looks up. They are not
        /// JWTs and carry no claims. The kind changes the default size and the handling advice, because a
        /// refresh token that lives for months is not the same risk as an access token that lives for
        /// minutes.
        /// </remarks>
        [HttpPost("oauth-token")]
        [ProducesResponseType<DeveloperSecretResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateOAuthToken(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] OAuthTokenRequest? request = null) =>
            Ok(ToResponse(secrets.GenerateOAuthToken(ToSpec(request))));

        /// <summary>
        /// Generates a key in the shape of a named AI provider's API key.
        /// </summary>
        /// <param name="request">
        /// Provider name from <c>GET /api/developer/ai-key/providers</c>. Omit the body for
        /// <c>generic</c>.
        /// </param>
        /// <returns>Returns the key, always with a warning that it is not a working provider credential.</returns>
        /// <remarks>
        /// The value has the provider's prefix, character set and a comparable length, and nothing else. It
        /// is random material from this API: it will not authenticate against that provider and it is not
        /// derived from any real credential. It exists so development, fixtures, tests and secret-scanner
        /// rules have something realistic to work with while the real key stays in its vault.
        /// </remarks>
        [HttpPost("ai-key")]
        [ProducesResponseType<DeveloperSecretResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateAiKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AiKeyRequest? request = null)
        {
            var provider = AiKeyProviderCatalog.Resolve(request?.Provider);

            return Ok(ToResponse(secrets.GenerateApiKey(provider.Spec), provider));
        }

        /// <summary>
        /// Lists the AI provider key formats this API can imitate.
        /// </summary>
        /// <returns>Returns one entry per provider. No key is generated, so this response holds no secret.</returns>
        [HttpGet("ai-key/providers")]
        [ProducesResponseType<IEnumerable<AiKeyProviderResponse>>(StatusCodes.Status200OK)]
        public IActionResult GetAiKeyProviders() =>
            Ok(AiKeyProviderCatalog.All.Select(provider => new AiKeyProviderResponse
            {
                Name = provider.Name,
                DisplayName = provider.DisplayName,
                Description = provider.Description,
                Bytes = provider.Spec.Bytes,
                Prefix = provider.Spec.Prefix,
                Warnings = provider.Advisories
            }));

        /// <summary>
        /// Generates the random values a WebAuthn registration needs: a single-use challenge and an opaque
        /// user handle.
        /// </summary>
        /// <param name="request">
        /// Sizes of the two values. Omit the body for a 32-byte challenge and a 64-byte user handle.
        /// </param>
        /// <returns>Returns both values Base64url encoded, with the rules for using them.</returns>
        /// <remarks>
        /// Only these two values can come from a server. The credential ID and the credential public key
        /// are produced by the authenticator during registration and returned by the browser, so they are
        /// deliberately absent from the response rather than being invented here.
        /// </remarks>
        [HttpPost("webauthn-credential")]
        [ProducesResponseType<WebAuthnCredentialResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateWebAuthnCredential(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] WebAuthnRequest? request = null) =>
            Ok(ToResponse(secrets.GenerateWebAuthnCredential(ToSpec(request))));

        /// <summary>
        /// Generates a random string of a requested length from a named or caller-supplied alphabet.
        /// </summary>
        /// <param name="request">
        /// Length and alphabet. Omit the body for 32 characters of digits and letters.
        /// </param>
        /// <returns>Returns the string with the entropy that many characters from that alphabet carries.</returns>
        /// <remarks>
        /// This is the endpoint for a value that has to fit a fixed-width field or a particular character
        /// set. Where the requirement is a key or a token, prefer the endpoint named after it: those size
        /// themselves correctly and return the advisories that go with that kind of credential.
        /// </remarks>
        [HttpPost("random-string")]
        [ProducesResponseType<DeveloperSecretResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateRandomString(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] RandomStringRequest? request = null) =>
            Ok(ToResponse(secrets.GenerateRandomString(ToSpec(request))));

        /// <summary>
        /// Generates a VAPID key pair for Web Push.
        /// </summary>
        /// <returns>
        /// Returns an ECDSA P-256 pair in the raw Base64url form Web Push libraries use and in the standard
        /// PEM forms.
        /// </returns>
        /// <remarks>
        /// There are no options because RFC 8292 allows only P-256. Generate one pair and keep it: every
        /// push subscription is bound to the public key it was created with, so rotating the pair silently
        /// invalidates all of them.
        /// </remarks>
        [HttpPost("vapid-key")]
        [ProducesResponseType<VapidKeyResponse>(StatusCodes.Status200OK)]
        public IActionResult GenerateVapidKey() => Ok(ToResponse(secrets.GenerateVapidKey()));

        /// <summary>
        /// Maps the optional API key request to generator options, leaving anything the caller omitted at
        /// its default.
        /// </summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static ByteSecretSpec ToSpec(ApiKeyRequest? request)
        {
            var defaults = new ByteSecretSpec();

            if (request is null)
            {
                return defaults;
            }

            return new ByteSecretSpec
            {
                Bytes = request.Bytes ?? defaults.Bytes,
                Encoding = DeveloperSecretOptions.ParseEncoding(request.Encoding, defaults.Encoding),
                Prefix = request.Prefix ?? defaults.Prefix
            };
        }

        /// <summary>Maps the optional JWT secret request to generator options.</summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static JwtSecretSpec ToSpec(JwtSecretRequest? request)
        {
            var defaults = new JwtSecretSpec();

            if (request is null)
            {
                return defaults;
            }

            return new JwtSecretSpec
            {
                Algorithm = DeveloperSecretOptions.ParseJwtAlgorithm(request.Algorithm),
                Encoding = DeveloperSecretOptions.ParseEncoding(request.Encoding, defaults.Encoding)
            };
        }

        /// <summary>Maps the optional OAuth token request to generator options.</summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static OAuthTokenSpec ToSpec(OAuthTokenRequest? request)
        {
            var defaults = new OAuthTokenSpec();

            if (request is null)
            {
                return defaults;
            }

            return new OAuthTokenSpec
            {
                Kind = DeveloperSecretOptions.ParseOAuthTokenKind(request.Kind),

                // Left null on purpose when the caller omitted it: the default size depends on the kind,
                // which the specification works out for itself.
                Bytes = request.Bytes,
                Encoding = DeveloperSecretOptions.ParseEncoding(request.Encoding, defaults.Encoding)
            };
        }

        /// <summary>Maps the optional WebAuthn request to generator options.</summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static WebAuthnSpec ToSpec(WebAuthnRequest? request)
        {
            var defaults = new WebAuthnSpec();

            if (request is null)
            {
                return defaults;
            }

            return new WebAuthnSpec
            {
                ChallengeBytes = request.ChallengeBytes ?? defaults.ChallengeBytes,
                UserHandleBytes = request.UserHandleBytes ?? defaults.UserHandleBytes
            };
        }

        /// <summary>Maps the optional random string request to generator options.</summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static RandomStringSpec ToSpec(RandomStringRequest? request)
        {
            var defaults = new RandomStringSpec();

            if (request is null)
            {
                return defaults;
            }

            return new RandomStringSpec
            {
                Length = request.Length ?? defaults.Length,
                Alphabet = DeveloperSecretOptions.ParseAlphabet(request.Alphabet),
                CustomAlphabet = request.CustomAlphabet ?? defaults.CustomAlphabet
            };
        }

        /// <summary>Maps a generated secret to the response.</summary>
        /// <param name="generated">The generated value and its figures.</param>
        private static DeveloperSecretResponse ToResponse(GeneratedSecret generated) => new()
        {
            Value = generated.Value,
            Length = generated.Length,
            EntropyBits = generated.EntropyBits,
            Strength = generated.Strength,
            Composition = generated.Composition,
            Kind = generated.Kind,
            Warnings = generated.Warnings
        };

        /// <summary>
        /// Maps a generated provider key to the response, naming the provider and putting its advisories —
        /// including the reminder that the value is not a working credential — ahead of the generator's.
        /// </summary>
        /// <param name="generated">The generated value and its figures.</param>
        /// <param name="provider">The provider whose format was imitated.</param>
        private static DeveloperSecretResponse ToResponse(
            GeneratedSecret generated,
            AiKeyProvider provider) => new()
            {
                Value = generated.Value,
                Length = generated.Length,
                EntropyBits = generated.EntropyBits,
                Strength = generated.Strength,
                Composition = generated.Composition,
                Kind = provider.Name,
                Warnings = Merge(provider.Advisories, generated.Warnings)
            };

        /// <summary>Maps generated WebAuthn values to the response.</summary>
        /// <param name="generated">The generated values and their sizes.</param>
        private static WebAuthnCredentialResponse ToResponse(
            GeneratedWebAuthnCredential generated) => new()
            {
                Challenge = generated.Challenge,
                UserHandle = generated.UserHandle,
                ChallengeBytes = generated.ChallengeBytes,
                UserHandleBytes = generated.UserHandleBytes,
                Format = generated.Format,
                Warnings = generated.Warnings
            };

        /// <summary>Maps a generated VAPID pair to the response.</summary>
        /// <param name="generated">The generated pair.</param>
        private static VapidKeyResponse ToResponse(GeneratedVapidKey generated) => new()
        {
            PublicKey = generated.PublicKey,
            PrivateKey = generated.PrivateKey,
            PublicKeyPem = generated.PublicKeyPem,
            PrivateKeyPem = generated.PrivateKeyPem,
            Curve = generated.Curve,
            Format = generated.Format,
            Warnings = generated.Warnings
        };

        /// <summary>
        /// Joins the advisories a provider carries to the ones the generator produced, so neither set is
        /// lost when a key comes from a named provider.
        /// </summary>
        /// <param name="providerWarnings">Advisories from the provider.</param>
        /// <param name="generated">Advisories from the generator.</param>
        private static IReadOnlyList<string> Merge(
            IReadOnlyList<string> providerWarnings,
            IReadOnlyList<string> generated)
        {
            if (providerWarnings.Count == 0)
            {
                return generated;
            }

            var merged = new List<string>(providerWarnings.Count + generated.Count);
            merged.AddRange(providerWarnings);
            merged.AddRange(generated);

            return merged;
        }
    }
}
