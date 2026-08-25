using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>Envelope method identifiers written into the envelope header.</summary>
    internal static class EnvelopeMethodId
    {
        internal const byte AesGcm = 0x01;
        internal const byte RsaOaep = 0x02;
        internal const byte EcdhAesGcm = 0x03;
    }

    /// <summary>
    /// Wraps ciphertext together with the parameters required to reverse the operation, so that a
    /// single opaque value can be handed to the matching decryption method.
    /// </summary>
    /// <remarks>
    /// Layout: <c>[1 byte format version][1 byte method id][method specific payload]</c>.
    /// The method id lets a mismatched method be reported clearly instead of surfacing as an
    /// authentication failure, and the version byte allows the layout to evolve without ambiguity.
    /// This is framing only - it provides no confidentiality and is not a cryptographic primitive.
    /// </remarks>
    internal static class CryptoEnvelope
    {
        /// <summary>Current envelope format version.</summary>
        internal const byte CurrentVersion = 0x01;

        /// <summary>Length of the fixed envelope header in bytes.</summary>
        internal const int HeaderLength = 2;

        /// <summary>Prefixes <paramref name="payload"/> with the envelope header.</summary>
        internal static byte[] Wrap(byte methodId, ReadOnlySpan<byte> payload)
        {
            var envelope = new byte[HeaderLength + payload.Length];
            envelope[0] = CurrentVersion;
            envelope[1] = methodId;
            payload.CopyTo(envelope.AsSpan(HeaderLength));
            return envelope;
        }

        /// <summary>
        /// Validates the envelope header and returns the method specific payload.
        /// </summary>
        /// <param name="envelope">Decoded envelope bytes.</param>
        /// <param name="expectedMethodId">Method id the caller's chosen method expects.</param>
        /// <exception cref="CryptographicRequestException">The envelope is truncated, uses an unknown version, or was produced by a different method.</exception>
        internal static ReadOnlySpan<byte> Unwrap(byte[] envelope, byte expectedMethodId)
        {
            if (envelope.Length < HeaderLength)
            {
                throw new CryptographicRequestException("The encrypted message is malformed.");
            }

            if (envelope[0] != CurrentVersion)
            {
                throw new CryptographicRequestException(
                    $"Unsupported encrypted message format version {envelope[0]}. This API produces version {CurrentVersion}.");
            }

            if (envelope[1] != expectedMethodId)
            {
                throw new CryptographicRequestException(
                    "The encrypted message was produced by a different encryption method. Use the method that produced it.");
            }

            return envelope.AsSpan(HeaderLength);
        }
    }
}
