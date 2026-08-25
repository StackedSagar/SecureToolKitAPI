using SecureToolKitAPI.Application;
using SecureToolKitAPI.Contracts.Passwords;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates human-facing secrets: passwords, passphrases, pronounceable values, PINs, and the
    /// usernames that go with them. Generation lives in <see cref="IPasswordGenerator"/>; this
    /// controller maps the request, names a preset and maps the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These endpoints use POST with an optional body. Nothing is taken from the URL except the name of
    /// a preset, so no generated value and no caller-supplied option ends up in a server or proxy access
    /// log.
    /// </para>
    /// <para>
    /// Every response contains secret material, except the username suggestion. Callers must treat it as
    /// sensitive: it is not logged here, and it should not be logged, cached or committed downstream.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/password")]
    [Produces("application/json")]
    public class PasswordGeneratorController(IPasswordGenerator passwords) : ControllerBase
    {
        /// <summary>
        /// Generates a random password.
        /// </summary>
        /// <param name="request">
        /// Length and character sets. Omit the body for the default: 16 characters from every set, with
        /// at least one character from each.
        /// </param>
        /// <returns>Returns the password with its measured strength.</returns>
        [HttpPost]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult Generate(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] PasswordRequest? request = null) =>
            Ok(ToResponse(passwords.Generate(ToSpec(request))));

        /// <summary>
        /// Generates several independent passwords in one request, for example when provisioning a batch
        /// of accounts.
        /// </summary>
        /// <param name="request">
        /// How many passwords to generate, and the options they share. Omit the body for ten passwords
        /// with the default options.
        /// </param>
        /// <returns>Returns the requested number of passwords, each generated independently.</returns>
        [HttpPost("bulk")]
        [ProducesResponseType<BulkPasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateBulk(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] BulkPasswordRequest? request = null)
        {
            var defaults = new BulkPasswordSpec();

            var generated = passwords.GenerateBulk(new BulkPasswordSpec
            {
                Count = request?.Count ?? defaults.Count,
                Password = ToSpec(request?.Password)
            });

            return Ok(new BulkPasswordResponse
            {
                Count = generated.Count,
                Passwords = [.. generated.Select(password => ToResponse(password))]
            });
        }

        /// <summary>
        /// Generates a passphrase: several words chosen independently from a fixed word list.
        /// </summary>
        /// <param name="request">
        /// Word count, separator and decorations. Omit the body for six hyphen-separated words.
        /// </param>
        /// <returns>Returns the passphrase with its measured strength.</returns>
        /// <remarks>
        /// A passphrase of the same strength as a random password is longer but far easier to type from
        /// memory, which is why it is offered separately.
        /// </remarks>
        [HttpPost("passphrase")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GeneratePassphrase(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] PassphraseRequest? request = null)
        {
            var defaults = new PassphraseSpec();

            return Ok(ToResponse(passwords.GeneratePassphrase(new PassphraseSpec
            {
                Words = request?.Words ?? defaults.Words,
                Separator = request?.Separator ?? defaults.Separator,
                Capitalize = request?.Capitalize ?? defaults.Capitalize,
                IncludeNumber = request?.IncludeNumber ?? defaults.IncludeNumber,
                IncludeSymbol = request?.IncludeSymbol ?? defaults.IncludeSymbol
            })));
        }

        /// <summary>
        /// Generates a memorable passphrase: four capitalised words joined by hyphens with a digit on the
        /// end, which satisfies most policies while staying easy to remember.
        /// </summary>
        /// <param name="request">Optional word count. Omit the body for four words.</param>
        /// <returns>Returns the passphrase with its measured strength.</returns>
        /// <remarks>
        /// This is the passphrase generator with a fixed, friendlier shape rather than a separate
        /// algorithm. Use <c>POST /api/password/passphrase</c> to control the shape, or ask for more words
        /// here when the extra strength is worth the extra typing.
        /// </remarks>
        [HttpPost("memorable")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateMemorable(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] MemorableRequest? request = null) =>
            Ok(ToResponse(passwords.GeneratePassphrase(new PassphraseSpec
            {
                Words = request?.Words ?? 4,
                Separator = "-",
                Capitalize = true,
                IncludeNumber = true
            })));

        /// <summary>
        /// Generates a pronounceable value from alternating consonant and vowel sounds.
        /// </summary>
        /// <param name="request">Syllable count and decorations. Omit the body for six syllables.</param>
        /// <returns>Returns the value with its measured strength, which is lower than a random password of the same length.</returns>
        [HttpPost("pronounceable")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GeneratePronounceable(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] PronounceableRequest? request = null)
        {
            var defaults = new PronounceableSpec();

            return Ok(ToResponse(passwords.GeneratePronounceable(new PronounceableSpec
            {
                Syllables = request?.Syllables ?? defaults.Syllables,
                Capitalize = request?.Capitalize ?? defaults.Capitalize,
                IncludeNumber = request?.IncludeNumber ?? defaults.IncludeNumber
            })));
        }

        /// <summary>
        /// Generates a numeric PIN, for equipment that accepts nothing else.
        /// </summary>
        /// <param name="request">Number of digits. Omit the body for six digits.</param>
        /// <returns>Returns the PIN, always with a warning that a PIN is weak by construction.</returns>
        [HttpPost("pin")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GeneratePin(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] PinRequest? request = null)
        {
            var defaults = new PinSpec();

            return Ok(ToResponse(passwords.GeneratePin(new PinSpec
            {
                Length = request?.Length ?? defaults.Length
            })));
        }

        /// <summary>
        /// Suggests a username.
        /// </summary>
        /// <param name="request">Word count, separator and decorations. Omit the body for two words and a number.</param>
        /// <returns>Returns the suggestion, with a warning that a username is not a secret.</returns>
        [HttpPost("username")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateUsername(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] UsernameRequest? request = null)
        {
            var defaults = new UsernameSpec();

            return Ok(ToResponse(passwords.GenerateUsername(new UsernameSpec
            {
                Words = request?.Words ?? defaults.Words,
                Separator = request?.Separator ?? defaults.Separator,
                Capitalize = request?.Capitalize ?? defaults.Capitalize,
                IncludeNumber = request?.IncludeNumber ?? defaults.IncludeNumber
            })));
        }

        /// <summary>
        /// Generates a master password for a password manager or disk encryption: 24 characters from
        /// every character set.
        /// </summary>
        /// <returns>Returns the password with its measured strength.</returns>
        [HttpPost("master")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        public IActionResult GenerateMaster() => FromPreset("master");

        /// <summary>
        /// Generates a Wi-Fi pre-shared key: 20 letters and digits, with no punctuation for router pages
        /// and printed cards to mangle.
        /// </summary>
        /// <returns>Returns the key with its measured strength.</returns>
        [HttpPost("wifi")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        public IActionResult GenerateWifiKey() => FromPreset("wifi");

        /// <summary>
        /// Generates a password for a game or console account: 12 unambiguous letters and digits, so it
        /// can be entered on an on-screen keyboard.
        /// </summary>
        /// <returns>Returns the password with its measured strength.</returns>
        [HttpPost("gaming")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        public IActionResult GenerateGamingPassword() => FromPreset("gaming");

        /// <summary>
        /// Generates a short-lived credential to hand over once: 10 unambiguous letters and digits.
        /// </summary>
        /// <returns>Returns the credential, with a warning that it is meant to be changed on first use.</returns>
        [HttpPost("temporary")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        public IActionResult GenerateTemporaryPassword() => FromPreset("temporary");

        /// <summary>
        /// Lists the named presets and what each one produces.
        /// </summary>
        /// <returns>Returns one entry per preset. No password is generated, so this response holds no secret.</returns>
        [HttpGet("presets")]
        [ProducesResponseType<IEnumerable<PasswordPresetResponse>>(StatusCodes.Status200OK)]
        public IActionResult GetPresets() =>
            Ok(PasswordPresetCatalog.All.Select(preset => new PasswordPresetResponse
            {
                Name = preset.Name,
                Description = preset.Description,
                Length = preset.Spec.Length,
                Composition = preset.Spec.Describe(),
                Warnings = preset.Warnings
            }));

        /// <summary>
        /// Generates a password from a named preset.
        /// </summary>
        /// <param name="preset">
        /// Preset name from <c>GET /api/password/presets</c>, for example <c>wifi</c> or
        /// <c>numbers-only</c>. Matched case-insensitively.
        /// </param>
        /// <returns>Returns the password with its measured strength and any advisory the preset carries.</returns>
        [HttpPost("presets/{preset}")]
        [ProducesResponseType<PasswordResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateFromPreset(string preset) => FromPreset(preset);

        /// <summary>
        /// Resolves a preset, generates from it, and reports the preset's own advisories alongside the
        /// generator's.
        /// </summary>
        /// <param name="name">Preset name.</param>
        private IActionResult FromPreset(string name)
        {
            var preset = PasswordPresetCatalog.Resolve(name);

            return Ok(ToResponse(passwords.Generate(preset.Spec), preset.Name, preset.Warnings));
        }

        /// <summary>
        /// Maps the optional request to generator options, leaving anything the caller omitted at its
        /// default. A character set is included unless the caller explicitly excludes it.
        /// </summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static PasswordSpec ToSpec(PasswordRequest? request)
        {
            var defaults = new PasswordSpec();

            if (request is null)
            {
                return defaults;
            }

            var characters = PasswordCharacters.None;

            if (request.IncludeLowercase ?? true) characters |= PasswordCharacters.Lowercase;
            if (request.IncludeUppercase ?? true) characters |= PasswordCharacters.Uppercase;
            if (request.IncludeDigits ?? true) characters |= PasswordCharacters.Digits;
            if (request.IncludeSymbols ?? true) characters |= PasswordCharacters.Symbols;

            return new PasswordSpec
            {
                Length = request.Length ?? defaults.Length,
                Characters = characters,
                ExcludeAmbiguous = request.ExcludeAmbiguous ?? defaults.ExcludeAmbiguous,
                RequireEachSet = request.RequireEachSet ?? defaults.RequireEachSet
            };
        }

        /// <summary>
        /// Maps a generated value to the response, merging any preset advisories with the generator's.
        /// </summary>
        /// <param name="generated">The generated value and its figures.</param>
        /// <param name="preset">Preset the value came from, when it came from one.</param>
        /// <param name="presetWarnings">Advisories carried by that preset.</param>
        private static PasswordResponse ToResponse(
            GeneratedPassword generated,
            string? preset = null,
            IReadOnlyList<string>? presetWarnings = null) => new()
            {
                Value = generated.Value,
                Length = generated.Length,
                EntropyBits = generated.EntropyBits,
                Strength = generated.Strength,
                Composition = generated.Composition,
                Preset = preset,
                Warnings = Merge(presetWarnings, generated.Warnings)
            };

        /// <summary>
        /// Joins the advisories a preset carries to the ones the generator produced, so neither set is
        /// lost when a password comes from a preset.
        /// </summary>
        /// <param name="presetWarnings">Advisories from the preset, if any.</param>
        /// <param name="generated">Advisories from the generator.</param>
        private static IReadOnlyList<string> Merge(
            IReadOnlyList<string>? presetWarnings,
            IReadOnlyList<string> generated)
        {
            if (presetWarnings is null || presetWarnings.Count == 0)
            {
                return generated;
            }

            var merged = new List<string>(presetWarnings.Count + generated.Count);
            merged.AddRange(presetWarnings);
            merged.AddRange(generated);

            return merged;
        }
    }
}
