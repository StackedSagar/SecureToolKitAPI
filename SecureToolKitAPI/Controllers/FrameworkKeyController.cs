using SecureToolKitAPI.Contracts.Framework;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates the secret a web framework asks for by name: a Django <c>SECRET_KEY</c>, a Flask
    /// <c>SECRET_KEY</c>, a Laravel <c>APP_KEY</c> and the eight WordPress authentication keys and salts.
    /// Generation lives in <see cref="IFrameworkKeyGenerator"/>; this controller maps the request and maps
    /// the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These endpoints exist because each framework wants a particular shape, not because a random string
    /// would be too hard to produce. Django's alphabet, the exact key length Laravel's configured cipher
    /// requires behind its <c>base64:</c> prefix, and WordPress's eight constants are all reproduced here, so
    /// a value generated for a framework is one that framework accepts.
    /// </para>
    /// <para>
    /// Every endpoint is a POST, because every one returns secret material and a URL ends up in server logs,
    /// proxy logs and browser history. There is no catalogue endpoint: the framework is already named in the
    /// route, so there is nothing to look up.
    /// </para>
    /// <para>
    /// Everything returned here is live secret material. It is returned once, this API does not store it or
    /// log it, and each value is drawn independently of every other. What differs between these keys and most
    /// of the rest of this API is the cost of replacing one: each response says what rotating it breaks,
    /// because for three of these four frameworks the answer is every existing session.
    /// </para>
    /// <para>
    /// Every endpoint accepts an omitted body, so a value outside a supported range is reported as this API's
    /// own problem response naming the range, rather than as a framework binding failure.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/framework")]
    [Produces("application/json")]
    public class FrameworkKeyController(IFrameworkKeyGenerator frameworks) : ControllerBase
    {
        /// <summary>
        /// Generates a Django <c>SECRET_KEY</c>.
        /// </summary>
        /// <param name="request">
        /// The key length. Omit the body for the default: 50 characters, which is what Django's own
        /// <c>get_random_secret_key()</c> produces.
        /// </param>
        /// <returns>Returns the key, and what depends on it.</returns>
        /// <remarks>
        /// This one value signs sessions, password reset tokens, CSRF tokens and signed cookies, so replacing
        /// it logs everyone out and invalidates every unused password reset link. Generate it once per
        /// environment, read it from the environment rather than from <c>settings.py</c>, and never share one
        /// between development and production.
        /// </remarks>
        [HttpPost("django")]
        [ProducesResponseType<FrameworkKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateDjangoSecretKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] DjangoSecretKeyRequest? request = null) =>
            Ok(ToResponse(frameworks.GenerateDjangoSecretKey(ToSpec(request))));

        /// <summary>
        /// Generates a Flask <c>SECRET_KEY</c>.
        /// </summary>
        /// <param name="request">
        /// Size and encoding. Omit the body for the default: 32 random bytes as hexadecimal, which is what
        /// <c>secrets.token_hex(32)</c> gives you.
        /// </param>
        /// <returns>Returns the key, with what it does and does not protect.</returns>
        /// <remarks>
        /// Flask signs its session cookie with this key rather than encrypting it, so the contents of a
        /// session are readable by the client and this key only stops the client changing them. Anything
        /// built on itsdangerous, including Flask-WTF's CSRF tokens, shares the same key by default.
        /// </remarks>
        [HttpPost("flask")]
        [ProducesResponseType<FrameworkKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateFlaskSecretKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] FlaskSecretKeyRequest? request = null) =>
            Ok(ToResponse(frameworks.GenerateFlaskSecretKey(ToSpec(request))));

        /// <summary>
        /// Generates a Laravel <c>APP_KEY</c>, sized for the configured cipher.
        /// </summary>
        /// <param name="request">
        /// The cipher the application is configured with. Omit the body for Laravel's default,
        /// <c>aes-256-cbc</c>.
        /// </param>
        /// <returns>Returns the key with the <c>base64:</c> prefix Laravel expects, and the cipher it fits.</returns>
        /// <remarks>
        /// The length is not a choice here: Laravel refuses to boot when the decoded key does not match
        /// <c>config('app.cipher')</c>, so the cipher decides the size. This key encrypts cookies, sessions,
        /// signed URLs and everything passed through <c>Crypt</c>, which means replacing it makes all of that
        /// undecryptable rather than merely invalid.
        /// </remarks>
        [HttpPost("laravel")]
        [ProducesResponseType<FrameworkKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateLaravelAppKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] LaravelAppKeyRequest? request = null) =>
            Ok(ToResponse(frameworks.GenerateLaravelAppKey(ToSpec(request))));

        /// <summary>
        /// Generates the eight WordPress authentication keys and salts, with the block to paste into
        /// <c>wp-config.php</c>.
        /// </summary>
        /// <param name="request">
        /// The length of each value. Omit the body for the default: 64 characters each, as WordPress's own
        /// salt service hands out.
        /// </param>
        /// <returns>Returns the eight named values and the configuration block containing them.</returns>
        /// <remarks>
        /// All eight are drawn independently, which is the whole point of having eight rather than one:
        /// compromising a cookie signed under one says nothing about the rest. Replacing them logs every user
        /// out immediately, which is what you want after a compromise. Never use a block copied from a
        /// tutorial or a paste bin, because a published salt is not a salt.
        /// </remarks>
        [HttpPost("wordpress-salts")]
        [ProducesResponseType<WordPressSaltsResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateWordPressSalts(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] WordPressSaltRequest? request = null) =>
            Ok(ToResponse(frameworks.GenerateWordPressSalts(ToSpec(request))));

        /// <summary>Maps the Django request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static DjangoSecretKeySpec ToSpec(DjangoSecretKeyRequest? request)
        {
            var defaults = new DjangoSecretKeySpec();

            if (request is null)
            {
                return defaults;
            }

            return new DjangoSecretKeySpec
            {
                Length = request.Length ?? defaults.Length
            };
        }

        /// <summary>Maps the Flask request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <remarks>
        /// The encoding names are the same ones the developer-secret endpoints accept, resolved by the same
        /// parser, so there is one spelling of <c>hex</c> across this API rather than one per controller.
        /// </remarks>
        private static FlaskSecretKeySpec ToSpec(FlaskSecretKeyRequest? request)
        {
            var defaults = new FlaskSecretKeySpec();

            if (request is null)
            {
                return defaults;
            }

            return new FlaskSecretKeySpec
            {
                Bytes = request.Bytes ?? defaults.Bytes,
                Encoding = DeveloperSecretOptions.ParseEncoding(request.Encoding, defaults.Encoding)
            };
        }

        /// <summary>Maps the Laravel request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static LaravelAppKeySpec ToSpec(LaravelAppKeyRequest? request)
        {
            var defaults = new LaravelAppKeySpec();

            if (request is null)
            {
                return defaults;
            }

            return new LaravelAppKeySpec
            {
                Cipher = FrameworkOptions.ParseLaravelCipher(request.Cipher)
            };
        }

        /// <summary>Maps the WordPress request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static WordPressSaltSpec ToSpec(WordPressSaltRequest? request)
        {
            var defaults = new WordPressSaltSpec();

            if (request is null)
            {
                return defaults;
            }

            return new WordPressSaltSpec
            {
                Length = request.Length ?? defaults.Length
            };
        }

        /// <summary>Maps a generated framework key onto the response contract.</summary>
        /// <param name="key">What the generator produced.</param>
        /// <remarks>
        /// The generator's <c>Kind</c> carries the Laravel cipher and is <c>null</c> for the other two
        /// frameworks, so it is surfaced under the name it actually has and omitted from the JSON when there
        /// is nothing to report.
        /// </remarks>
        private static FrameworkKeyResponse ToResponse(GeneratedFrameworkKey key) => new()
        {
            Framework = key.Framework,
            Setting = key.Setting,
            Value = key.Value,
            Length = key.Length,
            EntropyBits = key.EntropyBits,
            Strength = key.Strength,
            Composition = key.Composition,
            Cipher = key.Kind,
            Warnings = key.Warnings
        };

        /// <summary>Maps the generated WordPress values onto the response contract.</summary>
        /// <param name="salts">What the generator produced.</param>
        private static WordPressSaltsResponse ToResponse(GeneratedFrameworkSalts salts) => new()
        {
            Framework = salts.Framework,
            Salts =
            [
                .. salts.Salts.Select(salt => new FrameworkSaltResponse
                {
                    Name = salt.Name,
                    Value = salt.Value
                })
            ],
            Count = salts.Count,
            Length = salts.Length,
            EntropyBitsPerValue = salts.EntropyBits,
            Strength = salts.Strength,
            Composition = salts.Composition,
            Configuration = salts.Configuration,
            Warnings = salts.Warnings
        };
    }
}
