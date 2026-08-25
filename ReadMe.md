# SecureToolKitAPI

A .NET 10 ASP.NET Core Web API for generating cryptographic secrets and for encrypting, decrypting, signing, verifying and hashing messages. Every algorithm sits behind a common abstraction, so a caller selects a method by name and the API resolves it — adding a method means adding an implementation, not editing a controller.

The guiding constraint throughout is that this project never implements a cryptographic primitive by hand. Everything is built on `System.Security.Cryptography`, all randomness comes from `RandomNumberGenerator`, and encoding is kept conceptually distinct from encryption: Base64 is a transport format here, never a protection mechanism.

## Requirements

The .NET 10 SDK is the only prerequisite. The solution file is `SecureToolKitAPI.slnx`, the modern XML solution format, so a recent SDK and Visual Studio 2022/2026 or Rider are needed to open it.

## Running

```
dotnet run --project SecureToolKitAPI
```

The `https` launch profile serves `https://localhost:7180` and `http://localhost:5149`, sets `ASPNETCORE_ENVIRONMENT=Development` and opens Swagger UI. Swagger is registered only in Development and reads the generated XML documentation file, so every endpoint, parameter and response in the browser is the same text as the source comments. Liveness is exposed at `/health` and `/healthcheck`. Kestrel accepts request bodies up to 50 MB, which is what makes hashing a large payload in one request practical.

## Solution layout

```text
SecureToolKitAPI.slnx
├── SecureToolKitAPI/            API, Application and Cryptography layers
│   ├── Controllers/               12 controllers, thin, no algorithm logic
│   ├── Contracts/                 request/response records, grouped by area
│   ├── Application/               orchestration, registries, catalogues, DI composition
│   ├── Cryptography/              algorithms, generators, abstractions, internal helpers
│   ├── ExceptionHandling/         GlobalExceptionHandler (RFC 9457 problem responses)
│   └── Properties/                launch profiles
└── SecureToolKitAPI.Tests/      xUnit unit + integration tests
    ├── Unit/                      algorithm and generator behaviour
    ├── Integration/               full HTTP flow via WebApplicationFactory
    └── TestSupport/               shared scenarios, envelope editing, test keys
```

Dependencies point one way only: API depends on Application, Application depends on Cryptography, and Cryptography depends on neither. Controllers inject an application-service interface and nothing else, so no controller ever names a concrete algorithm.

## Architecture

Requests flow Controller → interface → service → cryptographic method. A controller validates nothing cryptographic itself; it maps a request contract to a spec, hands it to a service, and maps the result back. Each spec type is default-constructible, exposes `public const` bounds, validates itself through a `Validate()` method that throws `CryptographicRequestException`, and can describe itself in caller-safe text.

Method lookup goes through `CryptographicMethodRegistry<T>`, which indexes each implementation by its `Name` and its `Aliases` and throws at startup if two implementations claim the same identifier. That is why an unsupported method name produces a clean 400 listing the supported values rather than a null reference.

Dependency injection is composed in `Program.cs` as the single composition root, split by lifetime for a reason. `AddCryptographyMethods()` registers the algorithms, generators and registries as **singletons**, because they hold no per-caller state and are safe to share. `AddCryptographyApplicationServices()` registers the four orchestration services as **scoped**, one per request, leaving room for future per-request collaborators without creating a captive dependency. Every registration uses the `TryAdd` family, so composing a layer twice cannot duplicate a method identifier. `ValidateScopes` and `ValidateOnBuild` are enabled in all environments, which means a captive dependency or an unconstructible registration fails at startup rather than under load.

## Error handling

All failures become RFC 9457 `ProblemDetails` responses through `GlobalExceptionHandler`. A `CryptographicRequestException` carries text written deliberately for API consumers and becomes a `400` with `Invalid cryptographic request.` as the title and that text as the detail. Anything else is treated as a defect: it is logged server-side and returned as a bare `500` with no detail at all, so stack traces, platform cryptographic messages and key material cannot reach a caller.

Nothing sensitive is ever logged. The entire API contains exactly two logging statements, both in the exception handler, and both record only the HTTP method and path — never the request body, never the rejection reason, never key material.

## Endpoints

Verb choice is deliberate. GET is used only for catalogue listings that contain no secrets; anything that generates or accepts key material or a message uses POST with values in the body, so secrets never appear in a URL, a browser history or an access log.

### Key generation, encryption, decryption and signing

```text
GET  /api/keygen/methods                 list key generation methods
GET  /api/keygen/aes?keySize=256         AES-GCM key
GET  /api/keygen/rsa?keySize=2048        RSA key pair
GET  /api/keygen/EccHillman?keySize=256  ECDH key pair (P-256/384/521)
GET  /api/keygen/EccDss?keySize=256      ECDSA key pair
GET  /api/keygen/hmac?keySize=256        HMAC secret
GET  /api/keygen/random?keySize=512      raw random secret
POST /api/keygen/{method}                key generation with a request body

GET  /api/encrypt/methods                list encryption methods
POST /api/encrypt/{method}               encrypt a message
GET  /api/decrypt/methods                list decryption methods
POST /api/decrypt/{method}               decrypt an encrypted message

GET  /api/signature/methods              list signature methods
POST /api/signature/{method}/sign        sign a message
POST /api/signature/{method}/verify      verify a signature
```

The GET key-generation routes are the project's original surface and are kept working for backward compatibility. New work should prefer the POST routes under `/api/encryption`.

### Generators

```text
POST /api/password                       password, with full option control
POST /api/password/bulk                  many passwords in one call
POST /api/password/passphrase            wordlist passphrase
POST /api/password/memorable
POST /api/password/pronounceable
POST /api/password/pin
POST /api/password/username
POST /api/password/master
POST /api/password/wifi
POST /api/password/gaming
POST /api/password/temporary
GET  /api/password/presets               list presets
POST /api/password/presets/{preset}      generate from a named preset

POST /api/developer/api-key
POST /api/developer/jwt-secret
POST /api/developer/oauth-token
POST /api/developer/ai-key
GET  /api/developer/ai-key/providers     list AI provider key shapes
POST /api/developer/webauthn-credential
POST /api/developer/random-string
POST /api/developer/vapid-key

POST /api/encryption/encryption-key
POST /api/encryption/aes
POST /api/encryption/aes-256
POST /api/encryption/rsa
POST /api/encryption/hmac
POST /api/encryption/secret
POST /api/encryption/salt

POST /api/recovery/backup-codes
POST /api/recovery/recovery-key
POST /api/recovery/strength              assess a supplied password
POST /api/recovery/entropy               estimate entropy

POST /api/identity/uuid
POST /api/identity/totp-secret
POST /api/identity/totp-authenticator    secret plus otpauth:// URI
POST /api/identity/totp-code
POST /api/identity/base32
GET  /api/identity/test-cards            non-live test card numbers

POST /api/framework/django
POST /api/framework/flask
POST /api/framework/laravel
POST /api/framework/wordpress-salts

POST /api/network/ssh                    SSH key pair
GET  /api/network/ssh/key-types          supported SSH key types

POST /api/hash                           hash, algorithm chosen in the body
POST /api/hash/sha256                    SHA-256, algorithm fixed by the route
POST /api/hash/md5                       MD5, checksum use only
GET  /api/hash/algorithms                supported hash functions
```

## Supported methods

Method names are matched case-insensitively and ignore `-`, `_` and spaces, so `ecc-hillman`, `ECCHillman` and `ecc_hillman` all resolve to the same method.

| Purpose | Identifier | Aliases | Notes |
| --- | --- | --- | --- |
| Encryption | `aes-gcm` | `aes`, `aesgcm` | Authenticated symmetric encryption |
| Encryption | `rsa-oaep` | `rsa`, `rsaoaep` | Public key encrypts, private key decrypts; message size limited by modulus |
| Encryption | `ecc-hillman` | `ecchillman`, `ecdh`, `ecdh-aes-gcm` | Hybrid ECDH + AES-GCM, ECIES style, no practical size limit |
| Signing | `ecc-dss` | `eccdss`, `ecdsa` | Private key signs, public key verifies |
| Signing | `hmac-sha256` | `hmac`, `hmacsha256` | One shared secret both signs and verifies |
| Hashing | `sha256`, `sha384`, `sha512` | — | Default is SHA-256 |
| Hashing | `md5` | — | Reproducing legacy checksums only; reported as broken in every response |
| SSH | `rsa` | — | `ssh-rsa`, default 3072 bits |
| SSH | `ecdsa` | — | `ecdsa-sha2-nistp256` and larger curves |

Encrypted output is a versioned envelope carrying the format version, a method identifier and whatever the algorithm needs — a nonce and tag for AES-GCM, an authenticated ephemeral public key for the ECDH hybrid — so a ciphertext is self-describing and tampering is detected on decryption rather than silently producing wrong plaintext.

## Deliberate omissions

Some things are absent on purpose, and absence is the safer answer. **Ed25519** is not offered because .NET 10 exposes no Ed25519 primitive in `System.Security.Cryptography`, and hand-writing one would break the project's central rule; SSH therefore covers RSA and ECDSA only. **BCrypt, Argon2, PGP and WireGuard** are likewise not implemented rather than half-implemented. Password hashing in particular is not offered at all: the hash endpoints exist for integrity checksums, and every hash response says so explicitly, because a SHA-256 digest is the wrong tool for storing a password no matter how it is salted.

## Security posture

Secrets are treated as sensitive from the moment they are generated. Nothing generated, supplied or decrypted is ever written to a log. No key or secret is hard-coded anywhere; the only fixed alphabets in the source are the RFC 4648 and Crockford Base32 tables and the password character sets. Key sizes and algorithm parameters are validated before any cryptographic call, and error messages are restricted to bounds, counts, algorithm names and lists of supported values so that a rejection never echoes a caller's secret back. Every `catch (CryptographicException)` discards the exception and throws fixed, caller-safe text naming only the expected format.

A static review across logging, hard-coded secrets, error-message content and random number generation found no violations: all 20 randomness call sites use `RandomNumberGenerator`, and there are no uses of `System.Random`, `Random.Shared` or `Guid.NewGuid()` for anything security-bearing.

## Building and testing

```
dotnet build SecureToolKitAPI.slnx
dotnet test  SecureToolKitAPI.slnx
```

The suite is 694 `[Fact]` and `[Theory]` methods across 33 files — 20 unit and 13 integration — and theories expand to a larger number of executed cases. Unit tests cover each algorithm and generator directly; integration tests drive the real HTTP surface through `WebApplicationFactory<Program>`, including the full generate-key → encrypt → decrypt → original-message round trip. Coverage is deliberately weighted toward failure: invalid keys, wrong key for the method, corrupted and tampered ciphertext, unsupported method names, malformed Base64, empty and oversized input, and confirmation that problem responses never contain key material or internal type names.

Both the build and the full test suite pass on .NET 10.

## Adding a method

Implement the relevant abstraction — `IEncryptionMethod`, `ISignatureMethod` or `IKeyGenerator` — under its own folder in `Cryptography/`, giving it a unique `Name` and any `Aliases`. Register it with `TryAddEnumerable` in `AddCryptographyMethods()`. The registry picks it up, the existing `{method}` routes resolve it, and the `/methods` catalogues advertise it. No controller, contract or application service needs to change. Anything with its own request shape gets a contract under `Contracts/` and its own controller for that functional area, since a controller holds one category of endpoints and never becomes a catch-all.
