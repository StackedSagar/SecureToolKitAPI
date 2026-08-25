using System.Globalization;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Recovery
{
    /// <summary>
    /// Estimates the strength of a password that was supplied, and calculates the entropy of a password
    /// that would be generated to a given shape.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Estimate"/> is arithmetic: the entropy of <c>n</c> independent uniform choices from an
    /// alphabet of <c>s</c> symbols is exactly <c>n × log2(s)</c>.
    /// </para>
    /// <para>
    /// <see cref="Analyze"/> is harder and can only produce an upper bound, because the entropy of a
    /// password is a property of the process that produced it and that process is not recoverable from the
    /// result. What it does instead is count the candidates in each structural class the password belongs
    /// to and report the smallest of those counts. Four bounds are computed, each one the size of a set an
    /// attacker could enumerate:
    /// </para>
    /// <para>
    /// The <em>alphabet bound</em> is <c>log2(pool)</c> per position over the character classes present,
    /// except that a character equal to, one above or one below the character before it costs
    /// <c>log2(3)</c> instead — that is what a run such as <c>aaa</c> or a step such as <c>abc</c> is worth.
    /// </para>
    /// <para>
    /// The <em>distinct-character bound</em> is the cost of naming which distinct characters appear,
    /// <c>log2(C(pool, distinct))</c>, plus <c>log2(distinct)</c> per position. This is what bites on a
    /// password built from very few characters.
    /// </para>
    /// <para>
    /// The <em>shape bound</em> is the cost of naming where the character classes change,
    /// <c>log2(C(length - 1, runs - 1))</c>, plus the cost of naming the class of each run, plus
    /// <c>log2(class size)</c> for every position. This is what bites on the usual human shape — a word,
    /// then a digit or two, then a symbol — because so few unbroken runs are cheap to describe.
    /// </para>
    /// <para>
    /// The <em>repetition bound</em> applies when the whole password is a shorter block repeated: the cost
    /// is then only the cost of the block.
    /// </para>
    /// <para>
    /// None of this can tell whether a password is a common one or has appeared in a breach, which needs a
    /// corpus this API does not have. The result says so rather than implying the figure is the whole
    /// story.
    /// </para>
    /// <para>
    /// The password is never logged, stored, cached or echoed, and no finding quotes any part of it: they
    /// name patterns and classes only. The analyzer holds no state, which is why it is registered as a
    /// singleton.
    /// </para>
    /// </remarks>
    public sealed class PasswordAnalyzer : IPasswordAnalyzer
    {
        /// <summary>Number of lowercase ASCII letters.</summary>
        private const int LowercaseSize = 26;

        /// <summary>Number of uppercase ASCII letters.</summary>
        private const int UppercaseSize = 26;

        /// <summary>Number of decimal digits.</summary>
        private const int DigitSize = 10;

        /// <summary>
        /// Printable ASCII that is neither a letter nor a digit: 33 characters, counting the space.
        /// </summary>
        private const int AsciiSymbolSize = 33;

        /// <summary>
        /// How many character classes the shape bound has to choose between when naming the class of a run.
        /// </summary>
        private const int CharacterClassCount = 5;

        /// <summary>
        /// The three ways a character can continue the one before it: the same character, the next in
        /// order, or the previous one.
        /// </summary>
        private const double StepChoices = 3d;

        /// <summary>Length below which shortness is worth pointing out on its own.</summary>
        private const int RecommendedLength = 12;

        /// <summary>
        /// Fraction of the length at or below which the number of distinct characters is worth pointing
        /// out.
        /// </summary>
        private const double DistinctShareWorthReporting = 0.5d;

        /// <summary>Number of unbroken class runs at or below which the shape is worth pointing out.</summary>
        private const int RunsWorthReporting = 4;

        /// <summary>The classes a character can fall into, in the order they are described.</summary>
        private enum CharacterClass
        {
            /// <summary>Lowercase ASCII letter.</summary>
            Lowercase,

            /// <summary>Uppercase ASCII letter.</summary>
            Uppercase,

            /// <summary>Decimal digit.</summary>
            Digit,

            /// <summary>Printable ASCII that is neither a letter nor a digit, including the space.</summary>
            Symbol,

            /// <summary>Anything else: accented letters, other scripts, emoji, control characters.</summary>
            Other
        }

        /// <inheritdoc />
        public PasswordAssessment Analyze(string? password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new CryptographicRequestException("A password is required.");
            }

            // Bounded by what this API is willing to generate, so analysis cannot be used to hand the
            // process an unbounded amount of work.
            if (password.Length > PasswordSpec.MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"The password must be at most {PasswordSpec.MaximumLength} characters.");
            }

            var length = password.Length;
            var present = new HashSet<CharacterClass>();
            var outsideAscii = new HashSet<char>();
            var distinct = new HashSet<char>();
            var runs = 1;
            var predictable = 0;

            for (var index = 0; index < length; index++)
            {
                var character = password[index];
                var characterClass = ClassOf(character);

                present.Add(characterClass);
                distinct.Add(character);

                if (characterClass == CharacterClass.Other)
                {
                    outsideAscii.Add(character);
                }

                if (index == 0)
                {
                    continue;
                }

                var previous = password[index - 1];

                if (ClassOf(previous) != characterClass)
                {
                    runs++;
                }

                if (character == previous || character == previous + 1 || character == previous - 1)
                {
                    predictable++;
                }
            }

            var pool = Pool(present, outsideAscii.Count);
            var perCharacter = Math.Log2(pool);

            // A predictable character is never worth more than an unpredictable one, so the step cost is
            // capped: for a pool of two symbols, log2(3) would otherwise exceed log2(2).
            var stepBits = Math.Min(Math.Log2(StepChoices), perCharacter);

            var alphabetBound = ((length - predictable) * perCharacter) + (predictable * stepBits);
            var distinctBound = Log2Choose(pool, distinct.Count) + (length * Math.Log2(distinct.Count));
            var shapeBound = ShapeBound(password, length, runs, outsideAscii.Count);
            var block = ShortestRepeatedBlock(password);
            var repetitionBound = block * perCharacter;

            var bits = Math.Min(
                Math.Min(alphabetBound, distinctBound),
                Math.Min(shapeBound, repetitionBound));

            var rounded = PasswordStrength.Round(bits);
            var findings = Findings(length, distinct.Count, predictable, runs, block, present.Count);

            return new PasswordAssessment
            {
                Length = length,
                EntropyBits = rounded,
                Strength = PasswordStrength.Describe(rounded),
                Composition = Composition(present, pool),
                GuessesLog10 = PasswordStrength.Round(bits * Math.Log10(2)),
                Findings = findings,
                Warnings = AnalysisAdvice(rounded, findings.Count > 0)
            };
        }

        /// <inheritdoc />
        public EntropyEstimate Estimate(EntropySpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var alphabetSize = spec.ResolvedAlphabetSize();
            var bits = PasswordStrength.EntropyBits(spec.Count, alphabetSize);
            var rounded = PasswordStrength.Round(bits);

            return new EntropyEstimate
            {
                Count = spec.Count,
                AlphabetSize = alphabetSize,
                EntropyBitsPerCharacter = PasswordStrength.Round(Math.Log2(alphabetSize)),
                EntropyBits = rounded,
                Strength = PasswordStrength.Describe(rounded),
                Composition = spec.Describe(),
                GuessesLog10 = PasswordStrength.Round(bits * Math.Log10(2)),
                Warnings = EstimateAdvice(rounded)
            };
        }

        /// <summary>Which class a character belongs to.</summary>
        /// <param name="character">The character to classify.</param>
        private static CharacterClass ClassOf(char character) => character switch
        {
            >= 'a' and <= 'z' => CharacterClass.Lowercase,
            >= 'A' and <= 'Z' => CharacterClass.Uppercase,
            >= '0' and <= '9' => CharacterClass.Digit,
            >= ' ' and <= '~' => CharacterClass.Symbol,
            _ => CharacterClass.Other
        };

        /// <summary>Number of symbols in a class.</summary>
        /// <param name="characterClass">The class to size.</param>
        /// <param name="outsideAscii">
        /// Distinct characters seen outside ASCII. Used as the size of
        /// <see cref="CharacterClass.Other"/>, because there is no way to know which larger set they were
        /// chosen from — counting only what was seen keeps the estimate on the low side.
        /// </param>
        private static int ClassSize(CharacterClass characterClass, int outsideAscii) => characterClass switch
        {
            CharacterClass.Lowercase => LowercaseSize,
            CharacterClass.Uppercase => UppercaseSize,
            CharacterClass.Digit => DigitSize,
            CharacterClass.Symbol => AsciiSymbolSize,
            _ => Math.Max(outsideAscii, 1)
        };

        /// <summary>Caller-facing name of a class.</summary>
        /// <param name="characterClass">The class to name.</param>
        private static string Name(CharacterClass characterClass) => characterClass switch
        {
            CharacterClass.Lowercase => "lowercase",
            CharacterClass.Uppercase => "uppercase",
            CharacterClass.Digit => "digits",
            CharacterClass.Symbol => "ASCII symbols",
            _ => "characters outside ASCII"
        };

        /// <summary>
        /// Size of the alphabet the password appears to be drawn from: every symbol of every class that
        /// appears in it.
        /// </summary>
        /// <param name="present">Classes that appear.</param>
        /// <param name="outsideAscii">Distinct characters seen outside ASCII.</param>
        private static int Pool(HashSet<CharacterClass> present, int outsideAscii)
        {
            var pool = 0;

            foreach (var characterClass in present)
            {
                pool += ClassSize(characterClass, outsideAscii);
            }

            // Defensive: a non-empty password always reaches at least ten symbols, and log2 of anything
            // below two is not a number worth reporting.
            return Math.Max(pool, 2);
        }

        /// <summary>
        /// Cost of describing the password as a sequence of single-class runs and then filling each
        /// position from its own class.
        /// </summary>
        /// <param name="password">The password being assessed.</param>
        /// <param name="length">Its length.</param>
        /// <param name="runs">Number of unbroken single-class runs.</param>
        /// <param name="outsideAscii">Distinct characters seen outside ASCII.</param>
        private static double ShapeBound(string password, int length, int runs, int outsideAscii)
        {
            // Where the boundaries fall, then which class each run is: the first run has every class to
            // choose from and each following run has every class but the one before it.
            var shape = Log2Choose(length - 1, runs - 1)
                + Math.Log2(CharacterClassCount)
                + ((runs - 1) * Math.Log2(CharacterClassCount - 1));

            var mask = 0d;

            foreach (var character in password)
            {
                mask += Math.Log2(ClassSize(ClassOf(character), outsideAscii));
            }

            return shape + mask;
        }

        /// <summary>
        /// Length of the shortest block the whole password is a repetition of, or the length of the
        /// password when it is not a repetition of anything shorter.
        /// </summary>
        /// <param name="value">The password being assessed.</param>
        private static int ShortestRepeatedBlock(string value)
        {
            for (var block = 1; block <= value.Length / 2; block++)
            {
                if (value.Length % block != 0)
                {
                    continue;
                }

                var repeats = true;

                for (var index = block; index < value.Length && repeats; index++)
                {
                    repeats = value[index] == value[index - block];
                }

                if (repeats)
                {
                    return block;
                }
            }

            return value.Length;
        }

        /// <summary>
        /// Base two logarithm of "n choose k", summed term by term so it stays finite for sizes where the
        /// binomial coefficient itself would not.
        /// </summary>
        /// <param name="n">Size of the set to choose from.</param>
        /// <param name="k">Number of items chosen.</param>
        private static double Log2Choose(int n, int k)
        {
            if (k <= 0 || n <= 0)
            {
                return 0d;
            }

            var chosen = Math.Min(k, n);
            var total = 0d;

            for (var index = 0; index < chosen; index++)
            {
                total += Math.Log2((double)(n - index) / (index + 1));
            }

            return total;
        }

        /// <summary>Describes what the password is built from, without revealing any of it.</summary>
        /// <param name="present">Classes that appear.</param>
        /// <param name="pool">Size of the alphabet those classes add up to.</param>
        private static string Composition(HashSet<CharacterClass> present, int pool)
        {
            var names = Enum.GetValues<CharacterClass>()
                .Where(present.Contains)
                .Select(Name);

            return $"{string.Join(", ", names)} ({pool} character alphabet)";
        }

        /// <summary>
        /// What was noticed about the password's structure. Every finding names a pattern; none quotes a
        /// character.
        /// </summary>
        /// <param name="length">Length of the password.</param>
        /// <param name="distinct">Number of distinct characters in it.</param>
        /// <param name="predictable">Positions that continue the character before them.</param>
        /// <param name="runs">Number of unbroken single-class runs.</param>
        /// <param name="block">Length of the shortest repeated block, or the length when there is none.</param>
        /// <param name="classes">Number of character classes present.</param>
        private static IReadOnlyList<string> Findings(
            int length,
            int distinct,
            int predictable,
            int runs,
            int block,
            int classes)
        {
            var findings = new List<string>();

            if (length < RecommendedLength)
            {
                findings.Add(
                    $"{length} characters, shorter than the {RecommendedLength} a password should reach "
                    + "before its alphabet starts to matter.");
            }

            if (classes == 1)
            {
                findings.Add(
                    "Only one character class is used, so the alphabet is as small as it can be for this "
                    + "length.");
            }

            if (block < length)
            {
                findings.Add(
                    $"The whole password is a {block}-character block repeated {length / block} times, so "
                    + "it is worth no more than that block.");
            }

            if (predictable > 0)
            {
                findings.Add(
                    $"{predictable} of the {length} characters repeat the one before them or step one "
                    + "place along in character order, which costs a guesser almost nothing.");
            }

            if (distinct <= length * DistinctShareWorthReporting && length > 1)
            {
                findings.Add(
                    $"Only {distinct} distinct characters across {length} positions.");
            }

            if (runs <= RunsWorthReporting && length >= RecommendedLength && classes > 1)
            {
                findings.Add(
                    $"The character classes appear as {runs} unbroken runs, which is the shape most chosen "
                    + "passwords have — letters, then digits, then a symbol. A guesser who tries that "
                    + "shape first has far less work to do than the reported figure suggests.");
            }

            return findings;
        }

        /// <summary>What the caller should know about an estimate of a supplied password.</summary>
        /// <param name="entropyBits">The reported figure, already rounded.</param>
        /// <param name="hasFindings">Whether any structural pattern was noticed.</param>
        private static IReadOnlyList<string> AnalysisAdvice(double entropyBits, bool hasFindings)
        {
            var advice = new List<string>
            {
                "This figure is an upper bound inferred from the characters, not a measurement. Entropy is "
                + "a property of how a password was chosen, and that cannot be recovered from the password "
                + "itself.",
                "This check cannot tell whether the password is a common one or has appeared in a breach, "
                + "which is the most useful thing to know about it. Check it against a breach corpus "
                + "separately.",
                "The password was not logged, stored or echoed by this API, and no finding above quotes any "
                + "part of it."
            };

            if (hasFindings)
            {
                advice.Add(
                    "The patterns listed in the findings are priced generously, so the real number of "
                    + "guesses needed is lower than reported.");
            }

            if (entropyBits < PasswordStrength.AdvisoryThresholdBits)
            {
                var bits = entropyBits.ToString("0.#", CultureInfo.InvariantCulture);
                var threshold = PasswordStrength.AdvisoryThresholdBits.ToString("0", CultureInfo.InvariantCulture);

                advice.Add(
                    $"At most about {bits} bits, below the {threshold} bits worth relying on for an account "
                    + "password. Generating a password is more reliable than choosing one.");
            }

            return advice;
        }

        /// <summary>What the caller should know about a calculated entropy figure.</summary>
        /// <param name="entropyBits">The reported figure, already rounded.</param>
        private static IReadOnlyList<string> EstimateAdvice(double entropyBits)
        {
            var advice = new List<string>
            {
                "This figure holds only if every character is drawn independently and uniformly at random. "
                + "A value a person invented to fit the same pattern carries far less.",
                "No crack time is given. That would need an assumed guess rate, and the honest range spans "
                + "orders of magnitude depending on the password-hashing function, the hardware, and "
                + "whether the attack is online or offline."
            };

            if (entropyBits < PasswordStrength.AdvisoryThresholdBits)
            {
                var bits = entropyBits.ToString("0.#", CultureInfo.InvariantCulture);
                var threshold = PasswordStrength.AdvisoryThresholdBits.ToString("0", CultureInfo.InvariantCulture);

                advice.Add(
                    $"About {bits} bits, below the {threshold} bits worth relying on for an account "
                    + "password. Add characters or use a larger alphabet.");
            }

            return advice;
        }
    }
}
