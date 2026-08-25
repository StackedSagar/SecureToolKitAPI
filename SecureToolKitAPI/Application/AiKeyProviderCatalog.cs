using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>
    /// A named AI provider whose API key format can be imitated, so a caller can ask for "an OpenAI shaped
    /// key" instead of working out the prefix, size and encoding themselves.
    /// </summary>
    public sealed record AiKeyProvider
    {
        /// <summary>Identifier used in the request and in the provider listing, for example <c>openai</c>.</summary>
        public required string Name { get; init; }

        /// <summary>The provider's product name, as it is usually written.</summary>
        public required string DisplayName { get; init; }

        /// <summary>What the key looks like, and why the options below were chosen.</summary>
        public required string Description { get; init; }

        /// <summary>The options this provider's format implies.</summary>
        public required ByteSecretSpec Spec { get; init; }

        /// <summary>
        /// Advisories specific to this provider, beyond
        /// <see cref="AiKeyProviderCatalog.ImitationWarning"/>, which applies to all of them.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Everything a caller must be told about a key generated for this provider: that it only imitates
        /// the format, followed by anything specific to the provider.
        /// </summary>
        public IReadOnlyList<string> Advisories => [AiKeyProviderCatalog.ImitationWarning, .. Warnings];
    }

    /// <summary>
    /// The AI provider key formats the developer endpoints can imitate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A generated value has the shape of the provider's key — the same prefix, a comparable length and
    /// the same character set — and nothing else. It is random material from this API, so it will not
    /// authenticate against that provider, and it is not derived from any real credential. That is the
    /// point: it gives development, fixtures, tests and secret-scanner exercises something realistic to
    /// work with without a real key ever leaving its vault.
    /// </para>
    /// <para>
    /// Providers are data, not behaviour: each entry is a <see cref="ByteSecretSpec"/> with a name and an
    /// explanation, and generation still goes through
    /// <see cref="Cryptography.Abstractions.IDeveloperSecretGenerator"/>. Adding a provider is a single
    /// entry here.
    /// </para>
    /// <para>
    /// Formats drift as providers reissue keys, so the entries below aim at the shape rather than at an
    /// exact character count, and none of them claims to be current.
    /// </para>
    /// </remarks>
    public static class AiKeyProviderCatalog
    {
        /// <summary>
        /// The advisory attached to every generated provider key, so no caller can mistake one for a
        /// working credential.
        /// </summary>
        public const string ImitationWarning =
            "This value only imitates the shape of the provider's API key. It is random material generated "
            + "here, it will not authenticate against that provider, and it must not be presented as a real "
            + "credential. Treat it as a secret anyway if you use it as your own service's key.";

        private static readonly AiKeyProvider[] Providers =
        [
            .. new AiKeyProvider[]
            {
                new()
                {
                    Name = "openai",
                    DisplayName = "OpenAI",
                    Description =
                        "An sk- prefix followed by digits and letters. 256 bits of randomness rendered as "
                        + "Base62, which is the character set the real keys use.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 32,
                        Encoding = SecretEncoding.Base62,
                        Prefix = "sk-"
                    }
                },
                new()
                {
                    Name = "anthropic",
                    DisplayName = "Anthropic",
                    Description =
                        "An sk-ant- prefix followed by a long run of digits and letters. 384 bits, because "
                        + "these keys are noticeably longer than most.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 48,
                        Encoding = SecretEncoding.Base62,
                        Prefix = "sk-ant-"
                    }
                },
                new()
                {
                    Name = "azure-openai",
                    DisplayName = "Azure OpenAI Service",
                    Description =
                        "Lowercase hexadecimal with no prefix, 32 characters, which is the shape of an Azure "
                        + "resource key. 128 bits of randomness.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 16,
                        Encoding = SecretEncoding.Hex
                    },
                    Warnings =
                    [
                        "An Azure resource key is fixed at 32 hexadecimal characters, so this value carries "
                        + "128 bits rather than the 256 the other formats allow. That is ample for a key, but "
                        + "it is the format's ceiling rather than a choice made here."
                    ]
                },
                new()
                {
                    Name = "cohere",
                    DisplayName = "Cohere",
                    Description =
                        "Digits and letters with no prefix. 256 bits rendered as Base62.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 32,
                        Encoding = SecretEncoding.Base62
                    }
                },
                new()
                {
                    Name = "generic",
                    DisplayName = "Generic AI service",
                    Description =
                        "An ai_ prefix followed by a Base64url value. For your own service, when you want a "
                        + "recognisable prefix without imitating anyone else's format. 256 bits.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 32,
                        Encoding = SecretEncoding.Base64Url,
                        Prefix = "ai_"
                    }
                },
                new()
                {
                    Name = "google-ai",
                    DisplayName = "Google AI (Gemini)",
                    Description =
                        "An AIza prefix followed by digits and letters, the shape Google API keys have "
                        + "used for years. 256 bits rendered as Base62.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 32,
                        Encoding = SecretEncoding.Base62,
                        Prefix = "AIza"
                    }
                },
                new()
                {
                    Name = "huggingface",
                    DisplayName = "Hugging Face",
                    Description =
                        "An hf_ prefix followed by digits and letters. 256 bits rendered as Base62.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 32,
                        Encoding = SecretEncoding.Base62,
                        Prefix = "hf_"
                    }
                },
                new()
                {
                    Name = "mistral",
                    DisplayName = "Mistral AI",
                    Description =
                        "Digits and letters with no prefix. 256 bits rendered as Base62.",
                    Spec = new ByteSecretSpec
                    {
                        Bytes = 32,
                        Encoding = SecretEncoding.Base62
                    }
                }
            }.OrderBy(provider => provider.Name, StringComparer.OrdinalIgnoreCase)
        ];

        private static readonly Dictionary<string, AiKeyProvider> ByName = BuildIndex();

        /// <summary>All providers, ordered by name so the listing endpoint is stable.</summary>
        public static IReadOnlyList<AiKeyProvider> All => Providers;

        /// <summary>Names of all providers, ordered as in <see cref="All"/>.</summary>
        public static IReadOnlyList<string> Names => [.. Providers.Select(provider => provider.Name)];

        /// <summary>
        /// Resolves a provider by name, ignoring case and surrounding whitespace. An omitted name resolves
        /// to <c>generic</c>, so a caller who just wants an AI-shaped key does not have to pick a vendor.
        /// </summary>
        /// <param name="provider">Provider name supplied by the caller, or <c>null</c>.</param>
        /// <exception cref="CryptographicRequestException">The name is not supported.</exception>
        /// <remarks>
        /// The failure message lists the supported names, matching how
        /// <see cref="PasswordPresetCatalog.Resolve"/> and
        /// <see cref="CryptographicMethodRegistry{TMethod}"/> report an unknown name.
        /// </remarks>
        public static AiKeyProvider Resolve(string? provider)
        {
            if (string.IsNullOrWhiteSpace(provider))
            {
                return ByName["generic"];
            }

            if (ByName.TryGetValue(provider.Trim(), out var resolved))
            {
                return resolved;
            }

            throw new CryptographicRequestException(
                $"Unsupported provider '{provider.Trim()}'. Supported providers: {string.Join(", ", Names)}.");
        }

        /// <summary>Attempts to resolve a provider without throwing and without defaulting.</summary>
        /// <param name="provider">Provider name supplied by the caller.</param>
        /// <param name="resolved">The provider, when the name is known.</param>
        /// <returns><c>true</c> when the name is known.</returns>
        public static bool TryResolve(string? provider, out AiKeyProvider? resolved)
        {
            resolved = null;

            return !string.IsNullOrWhiteSpace(provider)
                && ByName.TryGetValue(provider.Trim(), out resolved);
        }

        /// <summary>
        /// Indexes the providers by name, and proves at type-initialisation time that every entry is
        /// uniquely named, actually valid, and that the default provider exists — a mistyped entry then
        /// fails immediately rather than producing a key of a surprising shape.
        /// </summary>
        private static Dictionary<string, AiKeyProvider> BuildIndex()
        {
            var index = new Dictionary<string, AiKeyProvider>(StringComparer.OrdinalIgnoreCase);

            foreach (var provider in Providers)
            {
                provider.Spec.Validate();

                if (!index.TryAdd(provider.Name, provider))
                {
                    throw new InvalidOperationException(
                        $"Provider '{provider.Name}' is defined more than once.");
                }
            }

            if (!index.ContainsKey("generic"))
            {
                throw new InvalidOperationException(
                    "The 'generic' provider is the default and must be defined.");
            }

            return index;
        }
    }
}
