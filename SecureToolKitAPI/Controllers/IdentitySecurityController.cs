using SecureToolKitAPI.Application;
using SecureToolKitAPI.Contracts.Identity;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates the values that identify an account and protect its second factor: UUIDs, TOTP shared
    /// secrets, the authenticator enrollment built around one, the code a secret currently produces, Base32
    /// rendering, and the published card numbers reserved for testing. Generation lives in
    /// <see cref="IIdentityGenerator"/>; this controller maps the request and maps the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The endpoints that carry secret material use POST with the values in the body, so no secret reaches a
    /// URL where it would be written to server logs, proxy logs and browser history. The two endpoints that
    /// only read published data — the identifiers are not secret either, but they are generated — follow the
    /// catalogue convention used elsewhere in this API: <c>test-cards</c> is a GET because it generates
    /// nothing at all.
    /// </para>
    /// <para>
    /// A TOTP secret is a complete second factor, and the enrollment URI contains it. Nothing supplied to or
    /// produced by these endpoints is logged, stored or cached by this API. A secret sent to the code
    /// endpoint is decoded, used and wiped, and it is not echoed in the response.
    /// </para>
    /// <para>
    /// Two things here deliberately do less than a caller might expect. <c>totp-code</c> computes a code and
    /// verifies nothing — the caller already holds the secret, so it could not be an authentication decision.
    /// <c>base32</c> is an encoding, not encryption, and says so on every response.
    /// </para>
    /// <para>
    /// Every endpoint accepts an omitted body so that a missing required value is reported as this API's own
    /// problem response, with a message naming what is missing, rather than as a framework binding failure.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/identity")]
    [Produces("application/json")]
    public class IdentitySecurityController(IIdentityGenerator identity) : ControllerBase
    {
        /// <summary>
        /// Generates one or more UUIDs.
        /// </summary>
        /// <param name="request">
        /// Count, version, format and casing. Omit the body for the default: one lowercase hyphenated
        /// version 4 identifier.
        /// </param>
        /// <returns>Returns the identifiers, with what they are and are not suitable for.</returns>
        /// <remarks>
        /// Version 4 is 122 random bits and nothing else. Version 7 puts a millisecond timestamp in front,
        /// so the values sort in creation order — useful as a database key, and a disclosure: anyone holding
        /// one can read when it was made, and the values either side of it are guessable.
        /// </remarks>
        [HttpPost("uuid")]
        [ProducesResponseType<UuidResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateUuids(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] UuidRequest? request = null) =>
            Ok(ToResponse(identity.GenerateUuids(ToSpec(request))));

        /// <summary>
        /// Generates a TOTP shared secret, Base32 encoded for entering into an authenticator.
        /// </summary>
        /// <param name="request">
        /// Size and the parameters the secret will be used with. Omit the body for the default: a 160-bit
        /// SHA-1 secret with six digit codes on a 30 second step, which every authenticator supports.
        /// </param>
        /// <returns>Returns the secret with the parameters it must be enrolled alongside.</returns>
        /// <remarks>
        /// The secret is the whole of the second factor: whatever holds it can produce valid codes for as
        /// long as the enrollment lasts. It is returned once, this API does not store it, and the algorithm,
        /// digits and period must be enrolled with it — a code only verifies when both sides agree on all
        /// three.
        /// </remarks>
        [HttpPost("totp-secret")]
        [ProducesResponseType<TotpSecretResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateTotpSecret(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] TotpSecretRequest? request = null) =>
            Ok(ToResponse(identity.GenerateTotpSecret(ToSpec(request))));

        /// <summary>
        /// Builds a complete authenticator enrollment: a secret and the <c>otpauth</c> URI a QR code is
        /// rendered from.
        /// </summary>
        /// <param name="request">
        /// Issuer and account are required, because an authenticator entry labelled with neither cannot be
        /// told apart from the others. Supply a secret only when re-issuing the URI for one that already
        /// exists.
        /// </param>
        /// <returns>Returns the secret and the URI, both of which are secret material.</returns>
        /// <remarks>
        /// The URI contains the secret, so a QR code made from it is a picture of the second factor: serve it
        /// over HTTPS, never log it, and do not let it be screenshotted into a support ticket. Confirm one
        /// code from the person's authenticator before relying on the enrollment, or somebody who never
        /// finished the scan will be locked out.
        /// </remarks>
        [HttpPost("totp-authenticator")]
        [ProducesResponseType<TotpEnrollmentResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult CreateTotpEnrollment(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] TotpEnrollmentRequest? request = null) =>
            Ok(ToResponse(identity.CreateTotpEnrollment(ToSpec(request))));

        /// <summary>
        /// Computes the code a supplied secret produces at a given moment.
        /// </summary>
        /// <param name="request">
        /// The Base32 secret and the parameters it was enrolled with. Omit the time for now, which is what
        /// checking an enrollment needs.
        /// </param>
        /// <returns>Returns the code, the counter it came from and how long it lasts.</returns>
        /// <remarks>
        /// <para>
        /// This verifies nothing and authenticates nobody. The caller supplies the secret, so anything
        /// calling this can already produce codes; it exists so an enrollment can be checked end to end
        /// against what the person's authenticator is showing.
        /// </para>
        /// <para>
        /// Verification belongs on your own server, against your own stored secret, with a small window
        /// either side for clock drift, single-use enforcement, rate limiting and a fixed-time comparison.
        /// The secret is read, used and wiped here; it is not logged, stored or echoed.
        /// </para>
        /// </remarks>
        [HttpPost("totp-code")]
        [ProducesResponseType<TotpCodeResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult ComputeTotpCode(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] TotpCodeRequest? request = null) =>
            Ok(ToResponse(identity.ComputeTotpCode(ToSpec(request))));

        /// <summary>
        /// Renders text or bytes as RFC 4648 Base32.
        /// </summary>
        /// <param name="request">
        /// The input as text or as Base64, and whether to pad and lowercase the result. Supply exactly one
        /// of the two inputs.
        /// </param>
        /// <returns>Returns the encoded value, always with the reminder that this is not encryption.</returns>
        /// <remarks>
        /// Base32 hides nothing: it is reversible by anyone, and the result is exactly as sensitive as the
        /// input it came from. It is here because a TOTP secret, a recovery code or a device identifier often
        /// has to be written in a form a person can read back accurately over the phone.
        /// </remarks>
        [HttpPost("base32")]
        [ProducesResponseType<EncodedTextResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult EncodeBase32(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] Base32Request? request = null) =>
            Ok(ToResponse(identity.EncodeBase32(ToSpec(request))));

        /// <summary>
        /// Lists the published card numbers reserved for testing, optionally narrowed to one network.
        /// </summary>
        /// <param name="brand">
        /// Which network's numbers to return, for example <c>visa</c> or <c>amex</c>. Omit for all of them.
        /// </param>
        /// <returns>
        /// Returns the matching numbers. Nothing here is generated and nothing here is secret.
        /// </returns>
        /// <remarks>
        /// These are the numbers the card networks publish for exactly this purpose. They are not issued to
        /// anybody and every real processor declines them. The list is fixed rather than generated on
        /// purpose: a random Luhn-valid number under a real issuer prefix could belong to an actual
        /// cardholder, and this endpoint would then be presenting it as safe to use.
        /// </remarks>
        [HttpGet("test-cards")]
        [ProducesResponseType<TestCardsResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GetTestCards([FromQuery] string? brand = null) =>
            Ok(ToResponse(TestCardCatalog.Resolve(brand)));

        /// <summary>Maps the UUID request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static UuidSpec ToSpec(UuidRequest? request)
        {
            var defaults = new UuidSpec();

            if (request is null)
            {
                return defaults;
            }

            return new UuidSpec
            {
                Count = request.Count ?? defaults.Count,
                Version = IdentityOptions.ParseUuidVersion(request.Version),
                Format = IdentityOptions.ParseUuidFormat(request.Format),
                Uppercase = request.Uppercase ?? defaults.Uppercase
            };
        }

        /// <summary>Maps the TOTP secret request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <remarks>
        /// The size is passed through unset rather than defaulted here, so the options can size the secret
        /// for whichever hash function was chosen.
        /// </remarks>
        private static TotpSecretSpec ToSpec(TotpSecretRequest? request)
        {
            var defaults = new TotpSecretSpec();

            if (request is null)
            {
                return defaults;
            }

            return new TotpSecretSpec
            {
                Bytes = request.Bytes,
                Parameters = ToParameters(request.Algorithm, request.Digits, request.PeriodSeconds)
            };
        }

        /// <summary>Maps the enrollment request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <remarks>
        /// The issuer and account are left as the empty defaults when they were not supplied, so the options
        /// report them as required rather than this mapper inventing a label.
        /// </remarks>
        private static TotpEnrollmentSpec ToSpec(TotpEnrollmentRequest? request)
        {
            var defaults = new TotpEnrollmentSpec();

            if (request is null)
            {
                return defaults;
            }

            return new TotpEnrollmentSpec
            {
                Issuer = request.Issuer ?? defaults.Issuer,
                Account = request.Account ?? defaults.Account,
                Secret = request.Secret,
                Bytes = request.Bytes,
                Parameters = ToParameters(request.Algorithm, request.Digits, request.PeriodSeconds)
            };
        }

        /// <summary>Maps the code request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static TotpCodeSpec ToSpec(TotpCodeRequest? request)
        {
            var defaults = new TotpCodeSpec();

            if (request is null)
            {
                return defaults;
            }

            return new TotpCodeSpec
            {
                Secret = request.Secret ?? defaults.Secret,
                Parameters = ToParameters(request.Algorithm, request.Digits, request.PeriodSeconds),
                UnixTimeSeconds = request.UnixTimeSeconds
            };
        }

        /// <summary>Maps the Base32 request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <remarks>
        /// Both inputs are passed through as supplied, including when both or neither were given, so the
        /// options can tell a caller which of those it was.
        /// </remarks>
        private static Base32Spec ToSpec(Base32Request? request)
        {
            var defaults = new Base32Spec();

            if (request is null)
            {
                return defaults;
            }

            return new Base32Spec
            {
                Text = request.Text,
                Base64 = request.Base64,
                Padding = request.Padding ?? defaults.Padding,
                Lowercase = request.Lowercase ?? defaults.Lowercase
            };
        }

        /// <summary>
        /// Resolves the three parameters an authenticator and a server must agree on, which every TOTP
        /// endpoint accepts in the same shape.
        /// </summary>
        /// <param name="algorithm">Caller-supplied algorithm name, or <c>null</c> for the default.</param>
        /// <param name="digits">Caller-supplied digit count, or <c>null</c> for the default.</param>
        /// <param name="periodSeconds">Caller-supplied time step, or <c>null</c> for the default.</param>
        private static TotpParameters ToParameters(string? algorithm, int? digits, int? periodSeconds)
        {
            var defaults = new TotpParameters();

            return new TotpParameters
            {
                Algorithm = IdentityOptions.ParseTotpAlgorithm(algorithm),
                Digits = digits ?? defaults.Digits,
                PeriodSeconds = periodSeconds ?? defaults.PeriodSeconds
            };
        }

        /// <summary>Maps the generated identifiers onto the response contract.</summary>
        /// <param name="uuids">What the generator produced.</param>
        private static UuidResponse ToResponse(GeneratedUuids uuids) => new()
        {
            Values = uuids.Values,
            Count = uuids.Values.Count,
            Version = uuids.Version,
            Format = uuids.Format,
            RandomBits = uuids.RandomBits,
            Composition = uuids.Composition,
            Warnings = uuids.Warnings
        };

        /// <summary>Maps the generated secret onto the response contract.</summary>
        /// <param name="secret">What the generator produced.</param>
        private static TotpSecretResponse ToResponse(GeneratedTotpSecret secret) => new()
        {
            Secret = secret.Secret,
            Bytes = secret.Bytes,
            EntropyBits = secret.EntropyBits,
            Strength = secret.Strength,
            Algorithm = secret.Algorithm,
            Digits = secret.Digits,
            PeriodSeconds = secret.PeriodSeconds,
            Composition = secret.Composition,
            Warnings = secret.Warnings
        };

        /// <summary>Maps the enrollment onto the response contract.</summary>
        /// <param name="enrollment">What the generator produced.</param>
        private static TotpEnrollmentResponse ToResponse(TotpEnrollment enrollment) => new()
        {
            Secret = enrollment.Secret,
            Uri = enrollment.Uri,
            Issuer = enrollment.Issuer,
            Account = enrollment.Account,
            Algorithm = enrollment.Algorithm,
            Digits = enrollment.Digits,
            PeriodSeconds = enrollment.PeriodSeconds,
            Bytes = enrollment.Bytes,
            Composition = enrollment.Composition,
            Warnings = enrollment.Warnings
        };

        /// <summary>Maps the computed code onto the response contract.</summary>
        /// <param name="code">What the generator computed.</param>
        private static TotpCodeResponse ToResponse(TotpCode code) => new()
        {
            Code = code.Code,
            UnixTimeSeconds = code.UnixTimeSeconds,
            Counter = code.Counter,
            ValidForSeconds = code.ValidForSeconds,
            Algorithm = code.Algorithm,
            Digits = code.Digits,
            PeriodSeconds = code.PeriodSeconds,
            Composition = code.Composition,
            Warnings = code.Warnings
        };

        /// <summary>Maps the encoded value onto the response contract.</summary>
        /// <param name="encoded">What the generator produced.</param>
        private static EncodedTextResponse ToResponse(EncodedText encoded) => new()
        {
            Value = encoded.Value,
            Encoding = encoded.Encoding,
            Bytes = encoded.Bytes,
            Length = encoded.Length,
            Composition = encoded.Composition,
            Warnings = encoded.Warnings
        };

        /// <summary>Maps the resolved test numbers onto the response contract.</summary>
        /// <param name="cards">The numbers the catalogue resolved.</param>
        /// <remarks>
        /// The Luhn result is read from the card rather than asserted, so the listing cannot claim something
        /// a number does not actually do.
        /// </remarks>
        private static TestCardsResponse ToResponse(IReadOnlyList<TestCard> cards) => new()
        {
            Cards =
            [
                .. cards.Select(card => new TestCardResponse
                {
                    Brand = card.Brand,
                    DisplayName = card.DisplayName,
                    Number = card.Number,
                    Digits = card.Digits,
                    SecurityCodeDigits = card.SecurityCodeDigits,
                    LuhnValid = card.LuhnValid,
                    Description = card.Description
                })
            ],
            Count = cards.Count,
            Brands = TestCardCatalog.Brands,
            Warnings = [TestCardCatalog.PublishedWarning]
        };
    }
}
