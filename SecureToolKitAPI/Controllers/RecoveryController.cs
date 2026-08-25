using SecureToolKitAPI.Contracts.Recovery;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates and assesses the credentials an account recovery flow needs: single-use backup codes, a
    /// standalone recovery key, a strength reading for a password a person chose, and the entropy of a
    /// password shape. Generation lives in <see cref="IRecoveryGenerator"/> and analysis in
    /// <see cref="IPasswordAnalyzer"/>; this controller maps the request and maps the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every endpoint here uses POST with the values in the body. That matters more on this controller than
    /// on any other: two of these routes carry live recovery credentials and one carries a password the
    /// caller already uses. None of it goes anywhere near a URL, where it would be written to server logs,
    /// proxy logs and browser history.
    /// </para>
    /// <para>
    /// Nothing supplied to or produced by these endpoints is logged, stored or cached by this API. The
    /// password sent to the strength check is read, measured and discarded; it is not echoed in the
    /// response and no finding quotes any part of it.
    /// </para>
    /// <para>
    /// The two analysis endpoints answer different questions and only one of them can be exact.
    /// <c>entropy</c> describes a password that does not exist yet, which is arithmetic. <c>strength</c>
    /// looks at one that does, which can only ever be an upper bound — the responses say so rather than
    /// letting a caller mistake one for the other.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/recovery")]
    [Produces("application/json")]
    public class RecoveryController(IRecoveryGenerator recovery, IPasswordAnalyzer analyzer) : ControllerBase
    {
        /// <summary>
        /// Generates a set of single-use backup codes, for the day a second factor is unavailable.
        /// </summary>
        /// <param name="request">
        /// Count, length, format and grouping. Omit the body for the default: ten 10-character
        /// alphanumeric codes in groups of five.
        /// </param>
        /// <returns>Returns the codes with the strength of one code and how they must be handled.</returns>
        /// <remarks>
        /// Each code is drawn independently, so one being used or leaked reveals nothing about the others.
        /// A code is short enough to write down by hand and is therefore weaker than a password on
        /// purpose: it is only safe where it is hashed at rest, invalidated on first use and rate-limited.
        /// The response says so in every case.
        /// </remarks>
        [HttpPost("backup-codes")]
        [ProducesResponseType<BackupCodesResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateBackupCodes(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] BackupCodeRequest? request = null) =>
            Ok(ToResponse(recovery.GenerateBackupCodes(ToSpec(request))));

        /// <summary>
        /// Generates a recovery key: one value, written in groups, that restores access on its own.
        /// </summary>
        /// <param name="request">
        /// Groups, group size and format. Omit the body for the default: five groups of five alphanumeric
        /// characters, about 125 bits.
        /// </param>
        /// <returns>Returns the key with its strength and how it must be stored and verified.</returns>
        /// <remarks>
        /// This is the strongest single credential in a recovery flow and usually the only one standing
        /// between an attacker and the account, with no second factor and often no rate limit, so it is
        /// sized to resist an offline attack rather than an online one.
        /// </remarks>
        [HttpPost("recovery-key")]
        [ProducesResponseType<RecoveryKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateRecoveryKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] RecoveryKeyRequest? request = null) =>
            Ok(ToResponse(recovery.GenerateRecoveryKey(ToSpec(request))));

        /// <summary>
        /// Estimates the strength of a password that was supplied rather than generated.
        /// </summary>
        /// <param name="request">The password to assess. Required; at most 512 characters.</param>
        /// <returns>Returns an upper bound on its strength and what lowered the estimate.</returns>
        /// <remarks>
        /// <para>
        /// The figure is an upper bound, not a measurement. Entropy is a property of how a password was
        /// chosen and that information is gone by the time it is a string, so this endpoint counts the
        /// candidates in the structural patterns it can see and reports the smallest count. A guesser who
        /// works out how the password was actually built needs fewer attempts than reported.
        /// </para>
        /// <para>
        /// It cannot tell whether the password is a common one or has appeared in a breach, which is the
        /// most useful thing to know about it and needs a corpus this API does not carry.
        /// </para>
        /// <para>
        /// The password is read, measured and discarded. It is not logged, not stored, not echoed, and no
        /// finding quotes any part of it.
        /// </para>
        /// </remarks>
        [HttpPost("strength")]
        [ProducesResponseType<PasswordStrengthResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult CheckStrength(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] PasswordStrengthRequest? request = null) =>
            Ok(ToResponse(analyzer.Analyze(request?.Password)));

        /// <summary>
        /// Calculates the entropy a password of a given length over a given alphabet would carry.
        /// </summary>
        /// <param name="request">
        /// Length and alphabet, the latter as character-set flags or as a bare size. Omit the body for the
        /// default: 16 characters from every character set.
        /// </param>
        /// <returns>Returns the entropy per character and in total, with what the figure assumes.</returns>
        /// <remarks>
        /// Nothing is generated and no password is accepted here: the answer is arithmetic on a described
        /// choice, which is why it is exact where the strength check can only estimate. It holds only for a
        /// value actually drawn at random, not for one a person invented to fit the same pattern.
        /// </remarks>
        [HttpPost("entropy")]
        [ProducesResponseType<EntropyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult CalculateEntropy(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] EntropyRequest? request = null) =>
            Ok(ToResponse(analyzer.Estimate(ToSpec(request))));

        /// <summary>Maps the backup code request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static BackupCodeSpec ToSpec(BackupCodeRequest? request)
        {
            var defaults = new BackupCodeSpec();

            if (request is null)
            {
                return defaults;
            }

            return new BackupCodeSpec
            {
                Count = request.Count ?? defaults.Count,
                Length = request.Length ?? defaults.Length,
                Format = RecoveryOptions.ParseBackupCodeFormat(request.Format),
                GroupSize = request.GroupSize ?? defaults.GroupSize
            };
        }

        /// <summary>Maps the recovery key request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        private static RecoveryKeySpec ToSpec(RecoveryKeyRequest? request)
        {
            var defaults = new RecoveryKeySpec();

            if (request is null)
            {
                return defaults;
            }

            return new RecoveryKeySpec
            {
                Groups = request.Groups ?? defaults.Groups,
                GroupSize = request.GroupSize ?? defaults.GroupSize,
                Format = RecoveryOptions.ParseBackupCodeFormat(request.Format)
            };
        }

        /// <summary>Maps the entropy request onto the analyzer's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <remarks>
        /// The character sets are left unset when the caller named the alphabet by size alone, so the
        /// options can tell the two ways of describing an alphabet apart and refuse a request that used
        /// both. Naming any one set opts into the flags, and the sets not named then default to included,
        /// matching the password endpoints.
        /// </remarks>
        private static EntropySpec ToSpec(EntropyRequest? request)
        {
            var defaults = new EntropySpec();

            if (request is null)
            {
                return defaults;
            }

            var namedASet = request.IncludeLowercase is not null
                || request.IncludeUppercase is not null
                || request.IncludeDigits is not null
                || request.IncludeSymbols is not null;

            PasswordCharacters? characters = null;

            if (namedASet || request.AlphabetSize is null)
            {
                var selected = PasswordCharacters.None;

                if (request.IncludeLowercase ?? true) selected |= PasswordCharacters.Lowercase;
                if (request.IncludeUppercase ?? true) selected |= PasswordCharacters.Uppercase;
                if (request.IncludeDigits ?? true) selected |= PasswordCharacters.Digits;
                if (request.IncludeSymbols ?? true) selected |= PasswordCharacters.Symbols;

                characters = selected;
            }

            return new EntropySpec
            {
                Count = request.Count ?? defaults.Count,
                Characters = characters,
                ExcludeAmbiguous = request.ExcludeAmbiguous ?? defaults.ExcludeAmbiguous,
                AlphabetSize = request.AlphabetSize
            };
        }

        /// <summary>Maps the generated codes onto the response contract.</summary>
        /// <param name="codes">What the generator produced.</param>
        private static BackupCodesResponse ToResponse(GeneratedBackupCodes codes) => new()
        {
            Codes = codes.Codes,
            Count = codes.Codes.Count,
            Length = codes.Length,
            EntropyBitsPerCode = codes.EntropyBitsPerCode,
            Strength = codes.Strength,
            Composition = codes.Composition,
            Warnings = codes.Warnings
        };

        /// <summary>Maps the generated recovery key onto the response contract.</summary>
        /// <param name="key">What the generator produced.</param>
        private static RecoveryKeyResponse ToResponse(GeneratedRecoveryKey key) => new()
        {
            Value = key.Value,
            Characters = key.Characters,
            Groups = key.Groups,
            EntropyBits = key.EntropyBits,
            Strength = key.Strength,
            Composition = key.Composition,
            Warnings = key.Warnings
        };

        /// <summary>Maps the assessment onto the response contract.</summary>
        /// <param name="assessment">What the analyzer concluded.</param>
        private static PasswordStrengthResponse ToResponse(PasswordAssessment assessment) => new()
        {
            Length = assessment.Length,
            EntropyBits = assessment.EntropyBits,
            Strength = assessment.Strength,
            Composition = assessment.Composition,
            GuessesLog10 = assessment.GuessesLog10,
            Findings = assessment.Findings,
            Warnings = assessment.Warnings
        };

        /// <summary>Maps the entropy calculation onto the response contract.</summary>
        /// <param name="estimate">What the analyzer calculated.</param>
        private static EntropyResponse ToResponse(EntropyEstimate estimate) => new()
        {
            Count = estimate.Count,
            AlphabetSize = estimate.AlphabetSize,
            EntropyBitsPerCharacter = estimate.EntropyBitsPerCharacter,
            EntropyBits = estimate.EntropyBits,
            Strength = estimate.Strength,
            Composition = estimate.Composition,
            GuessesLog10 = estimate.GuessesLog10,
            Warnings = estimate.Warnings
        };
    }
}
