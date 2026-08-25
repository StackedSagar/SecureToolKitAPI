namespace SecureToolKitAPI.Tests.TestSupport
{
    /// <summary>
    /// Edits an encrypted envelope so tests can simulate corruption, truncation and tampering.
    /// </summary>
    /// <remarks>
    /// Offsets mirror the documented envelope layout: byte 0 is the format version and byte 1 is the
    /// method identifier, followed by the method specific payload.
    /// </remarks>
    public static class EnvelopeEditor
    {
        /// <summary>Index of the format version byte.</summary>
        public const int VersionIndex = 0;

        /// <summary>Index of the method identifier byte.</summary>
        public const int MethodIdIndex = 1;

        /// <summary>Index of the first payload byte.</summary>
        public const int PayloadIndex = 2;

        /// <summary>Index of the first AES-GCM nonce byte for the <c>aes-gcm</c> layout.</summary>
        public const int AesGcmNonceIndex = PayloadIndex;

        /// <summary>Index of the first AES-GCM tag byte for the <c>aes-gcm</c> layout.</summary>
        public const int AesGcmTagIndex = AesGcmNonceIndex + 12;

        /// <summary>Index of the first AES-GCM ciphertext byte for the <c>aes-gcm</c> layout.</summary>
        public const int AesGcmCipherTextIndex = AesGcmTagIndex + 16;

        /// <summary>Decodes an envelope to raw bytes.</summary>
        public static byte[] Decode(string envelope) => Convert.FromBase64String(envelope);

        /// <summary>Encodes raw bytes as an envelope.</summary>
        public static string Encode(byte[] envelope) => Convert.ToBase64String(envelope);

        /// <summary>Inverts every bit of a single byte, leaving the length unchanged.</summary>
        public static string FlipByteAt(string envelope, int index)
        {
            var bytes = Decode(envelope);
            bytes[index] ^= 0xFF;
            return Encode(bytes);
        }

        /// <summary>Inverts every bit of the final byte.</summary>
        public static string FlipLastByte(string envelope)
        {
            var bytes = Decode(envelope);
            bytes[^1] ^= 0xFF;
            return Encode(bytes);
        }

        /// <summary>Keeps only the first <paramref name="length"/> bytes.</summary>
        public static string Truncate(string envelope, int length) => Encode(Decode(envelope)[..length]);

        /// <summary>Replaces a range of bytes with <paramref name="replacement"/>, which must be the same length.</summary>
        public static string Replace(string envelope, int index, byte[] replacement)
        {
            var bytes = Decode(envelope);
            replacement.CopyTo(bytes, index);
            return Encode(bytes);
        }

        /// <summary>Overwrites the method identifier byte.</summary>
        public static string WithMethodId(string envelope, byte methodId)
        {
            var bytes = Decode(envelope);
            bytes[MethodIdIndex] = methodId;
            return Encode(bytes);
        }

        /// <summary>Overwrites the format version byte.</summary>
        public static string WithVersion(string envelope, byte version)
        {
            var bytes = Decode(envelope);
            bytes[VersionIndex] = version;
            return Encode(bytes);
        }

        /// <summary>Length of the decoded envelope in bytes.</summary>
        public static int Length(string envelope) => Decode(envelope).Length;
    }
}
