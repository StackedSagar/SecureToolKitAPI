using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace SecureToolKitAPI.ExceptionHandling
{
    /// <summary>
    /// Translates exceptions into RFC 9457 problem responses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="CryptographicRequestException"/> carries a message that is written for API
    /// consumers, so it becomes a <c>400 Bad Request</c> with that message as the detail.
    /// </para>
    /// <para>
    /// Anything else is treated as a defect: it is logged server-side for diagnosis and returned as a
    /// bare <c>500</c>, so internal cryptographic details, stack traces and key material can never
    /// reach the caller. Request bodies are never logged.
    /// </para>
    /// </remarks>
    internal sealed class GlobalExceptionHandler(
        IProblemDetailsService problemDetailsService,
        ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
    {
        /// <inheritdoc />
        public async ValueTask<bool> TryHandleAsync(
            HttpContext httpContext,
            Exception exception,
            CancellationToken cancellationToken)
        {
            if (exception is CryptographicRequestException)
            {
                // Log that the request was rejected, but not the reason text and never the body:
                // callers get the detail in the response instead.
                logger.LogInformation(
                    "Rejected {RequestMethod} {RequestPath}: the cryptographic request was not valid.",
                    httpContext.Request.Method,
                    httpContext.Request.Path);

                return await WriteProblemAsync(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Invalid cryptographic request.",
                    exception.Message);
            }

            logger.LogError(
                exception,
                "Unhandled exception while processing {RequestMethod} {RequestPath}.",
                httpContext.Request.Method,
                httpContext.Request.Path);

            return await WriteProblemAsync(
                httpContext,
                StatusCodes.Status500InternalServerError,
                "An unexpected error occurred.",
                detail: null);
        }

        private async ValueTask<bool> WriteProblemAsync(
            HttpContext httpContext,
            int statusCode,
            string title,
            string? detail)
        {
            if (httpContext.Response.HasStarted)
            {
                return false;
            }

            httpContext.Response.StatusCode = statusCode;

            return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = httpContext,
                ProblemDetails = new ProblemDetails
                {
                    Status = statusCode,
                    Title = title,
                    Detail = detail,
                    Instance = httpContext.Request.Path
                }
            });
        }
    }
}
