using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>
    /// A named set of password options, so a caller can ask for "the Wi-Fi one" instead of restating
    /// length and character sets on every request.
    /// </summary>
    public sealed record PasswordPreset
    {
        /// <summary>Identifier used in the route and in the preset listing, for example <c>wifi</c>.</summary>
        public required string Name { get; init; }

        /// <summary>What the preset is for, and why its options were chosen.</summary>
        public required string Description { get; init; }

        /// <summary>The options this preset applies.</summary>
        public required PasswordSpec Spec { get; init; }

        /// <summary>
        /// Advisories that belong to the preset itself, such as a preset that is deliberately weaker
        /// than the default. Generator warnings are added to these, not replaced by them.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// The presets the password endpoints expose.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Presets are data, not behaviour: each one is only a <see cref="PasswordSpec"/> with a name and an
    /// explanation. Generation still goes through <see cref="IPasswordGenerator"/>, so a preset can
    /// never smuggle its own generation logic into the HTTP layer, and adding one is a single entry
    /// here.
    /// </para>
    /// <para>
    /// Several presets are deliberately weaker than the default because real systems impose real
    /// limits — routers that reject punctuation, consoles with on-screen keyboards, locks that take
    /// digits only. Each of those carries a warning rather than being silently offered as equivalent.
    /// </para>
    /// </remarks>
    public static class PasswordPresetCatalog
    {
        private static readonly PasswordPreset[] Presets =
        [
            .. new PasswordPreset[]
            {
                new()
                {
                    Name = "password",
                    Description =
                        "General-purpose account password: 16 characters from every character set. The default.",
                    Spec = new PasswordSpec()
                },
                new()
                {
                    Name = "master",
                    Description =
                        "Master password for a password manager or disk encryption: 24 characters from every "
                        + "set, because everything else depends on it.",
                    Spec = new PasswordSpec { Length = 24 }
                },
                new()
                {
                    Name = "wifi",
                    Description =
                        "Wi-Fi pre-shared key: 20 letters and digits. Symbols are omitted because many router "
                        + "administration pages and printed QR cards mangle them.",
                    Spec = new PasswordSpec { Length = 20, Characters = PasswordCharacters.Alphanumeric }
                },
                new()
                {
                    Name = "gaming",
                    Description =
                        "Console or game account password: 12 letters and digits with ambiguous characters "
                        + "removed, so it can be entered on an on-screen keyboard without misreading.",
                    Spec = new PasswordSpec
                    {
                        Length = 12,
                        Characters = PasswordCharacters.Alphanumeric,
                        ExcludeAmbiguous = true
                    }
                },
                new()
                {
                    Name = "temporary",
                    Description =
                        "Short-lived credential to hand over once: 10 unambiguous letters and digits, easy to "
                        + "read out loud.",
                    Spec = new PasswordSpec
                    {
                        Length = 10,
                        Characters = PasswordCharacters.Alphanumeric,
                        ExcludeAmbiguous = true
                    },
                    Warnings =
                    [
                        "This preset is intended for a credential that is used once and changed immediately. "
                        + "Do not leave it in place as an account password."
                    ]
                },
                new()
                {
                    Name = "easy-to-read",
                    Description =
                        "20 letters and digits with ambiguous characters removed, for a password that has to be "
                        + "read from a screen or dictated over the phone.",
                    Spec = new PasswordSpec
                    {
                        Length = 20,
                        Characters = PasswordCharacters.Alphanumeric,
                        ExcludeAmbiguous = true
                    }
                },
                new()
                {
                    Name = "letters-only",
                    Description =
                        "16 letters, for the occasional system that rejects digits and punctuation.",
                    Spec = new PasswordSpec { Length = 16, Characters = PasswordCharacters.LettersOnly }
                },
                new()
                {
                    Name = "no-symbols",
                    Description =
                        "16 letters and digits, for a system that rejects punctuation.",
                    Spec = new PasswordSpec { Length = 16, Characters = PasswordCharacters.Alphanumeric }
                },
                new()
                {
                    Name = "numbers-only",
                    Description =
                        "12 digits, for equipment that accepts nothing else.",
                    Spec = new PasswordSpec { Length = 12, Characters = PasswordCharacters.Digits },
                    Warnings =
                    [
                        "Digits alone carry about 3.3 bits per character, so this is far weaker than a value of "
                        + "the same length that mixes character sets. Use it only where nothing else is accepted."
                    ]
                },
                new()
                {
                    Name = "8-character",
                    Description = "8 characters from every set, for a length-capped legacy system.",
                    Spec = new PasswordSpec { Length = 8 },
                    Warnings =
                    [
                        "Eight characters is below what is recommended for an account password. Use a longer "
                        + "value wherever the system allows it."
                    ]
                },
                new()
                {
                    Name = "12-character",
                    Description = "12 characters from every set.",
                    Spec = new PasswordSpec { Length = 12 }
                },
                new()
                {
                    Name = "16-character",
                    Description = "16 characters from every set.",
                    Spec = new PasswordSpec { Length = 16 }
                },
                new()
                {
                    Name = "20-character",
                    Description = "20 characters from every set.",
                    Spec = new PasswordSpec { Length = 20 }
                },
                new()
                {
                    Name = "24-character",
                    Description = "24 characters from every set.",
                    Spec = new PasswordSpec { Length = 24 }
                },
                new()
                {
                    Name = "32-character",
                    Description = "32 characters from every set, at the point where a password is really a key.",
                    Spec = new PasswordSpec { Length = 32 }
                }
            }.OrderBy(preset => preset.Name, StringComparer.OrdinalIgnoreCase)
        ];

        private static readonly Dictionary<string, PasswordPreset> ByName = BuildIndex();

        /// <summary>All presets, ordered by name so the listing endpoint is stable.</summary>
        public static IReadOnlyList<PasswordPreset> All => Presets;

        /// <summary>Names of all presets, ordered as in <see cref="All"/>.</summary>
        public static IReadOnlyList<string> Names => [.. Presets.Select(preset => preset.Name)];

        /// <summary>
        /// Resolves a preset by name, ignoring case and surrounding whitespace.
        /// </summary>
        /// <param name="preset">Preset name supplied by the caller.</param>
        /// <exception cref="CryptographicRequestException">The name is missing or not supported.</exception>
        /// <remarks>
        /// The failure message lists the supported names, matching how
        /// <see cref="CryptographicMethodRegistry{TMethod}"/> reports an unknown method, so callers see
        /// one consistent style of error.
        /// </remarks>
        public static PasswordPreset Resolve(string? preset)
        {
            if (string.IsNullOrWhiteSpace(preset))
            {
                throw new CryptographicRequestException(
                    $"A preset is required. Supported presets: {string.Join(", ", Names)}.");
            }

            if (ByName.TryGetValue(preset.Trim(), out var resolved))
            {
                return resolved;
            }

            throw new CryptographicRequestException(
                $"Unsupported preset '{preset.Trim()}'. Supported presets: {string.Join(", ", Names)}.");
        }

        /// <summary>Attempts to resolve a preset without throwing.</summary>
        /// <param name="preset">Preset name supplied by the caller.</param>
        /// <param name="resolved">The preset, when the name is known.</param>
        /// <returns><c>true</c> when the name is known.</returns>
        public static bool TryResolve(string? preset, out PasswordPreset? resolved)
        {
            resolved = null;

            return !string.IsNullOrWhiteSpace(preset)
                && ByName.TryGetValue(preset.Trim(), out resolved);
        }

        /// <summary>
        /// Indexes the presets by name, and proves at type-initialisation time that every entry is
        /// uniquely named and actually valid — a mistyped preset then fails on the first request rather
        /// than producing a surprising password.
        /// </summary>
        private static Dictionary<string, PasswordPreset> BuildIndex()
        {
            var index = new Dictionary<string, PasswordPreset>(StringComparer.OrdinalIgnoreCase);

            foreach (var preset in Presets)
            {
                preset.Spec.Validate();

                if (!index.TryAdd(preset.Name, preset))
                {
                    throw new InvalidOperationException($"Preset '{preset.Name}' is defined more than once.");
                }
            }

            return index;
        }
    }
}
