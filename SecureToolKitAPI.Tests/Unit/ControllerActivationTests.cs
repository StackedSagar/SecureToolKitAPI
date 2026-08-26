using SecureToolKitAPI.Application;
using SecureToolKitAPI.Controllers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Verifies that every controller can actually be constructed from the services the API registers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This closes a gap that neither the compiler nor <c>ValidateOnBuild</c> covers. Controllers are not
    /// registered in the container: MVC builds them per request with
    /// <see cref="ActivatorUtilities"/>, so a constructor asking for a type nobody registered still
    /// compiles, still passes container validation at startup, and only fails when a request arrives —
    /// as a 500 on every route the controller owns.
    /// </para>
    /// <para>
    /// The specific mistake that motivated this test was a controller asking for the non-generic
    /// <c>ILogger</c>. Only <c>ILogger&lt;T&gt;</c> and <c>ILoggerFactory</c> are registered, so every
    /// request to that controller failed while the build stayed green.
    /// </para>
    /// <para>
    /// Nothing here generates or asserts a secret: only construction is exercised, and no action is
    /// invoked.
    /// </para>
    /// </remarks>
    public class ControllerActivationTests
    {
        [Fact]
        public void Every_controller_can_be_constructed_from_the_registered_services()
        {
            using var provider = BuildProvider();
            using var scope = provider.CreateScope();

            var failures = new List<string>();

            foreach (var controller in Controllers())
            {
                try
                {
                    var instance = ActivatorUtilities.CreateInstance(scope.ServiceProvider, controller);

                    (instance as IDisposable)?.Dispose();
                }
                catch (Exception exception)
                {
                    // The type name and the reason are enough to identify the missing registration, and
                    // neither can contain caller data: no request has been handled.
                    failures.Add($"{controller.Name}: {exception.Message}");
                }
            }

            Assert.True(
                failures.Count == 0,
                "A controller could not be constructed, so every request it handles would fail: "
                + string.Join(" | ", failures));
        }

        [Fact]
        public void The_controllers_are_discovered_so_the_activation_check_cannot_pass_by_finding_none()
        {
            var controllers = Controllers();

            Assert.NotEmpty(controllers);
            Assert.Contains(typeof(PasswordGeneratorController), controllers);
        }

        [Fact]
        public void A_controller_asking_for_an_unregistered_service_is_what_this_test_would_catch()
        {
            // Proves the check above can fail rather than passing for its own reasons: the non-generic
            // ILogger is exactly the dependency that broke the password endpoints.
            using var provider = BuildProvider();
            using var scope = provider.CreateScope();

            Assert.ThrowsAny<InvalidOperationException>(
                () => ActivatorUtilities.CreateInstance<UnregisteredDependencyController>(scope.ServiceProvider));
        }

        /// <summary>
        /// Builds the container the API builds, with the same validation, plus the logging that the web
        /// host adds for every application.
        /// </summary>
        private static ServiceProvider BuildProvider()
        {
            var services = new ServiceCollection();

            services.AddLogging();
            services.AddCryptography();

            return services.BuildServiceProvider(new ServiceProviderOptions
            {
                ValidateScopes = true,
                ValidateOnBuild = true
            });
        }

        /// <summary>Every concrete controller in the API assembly.</summary>
        private static Type[] Controllers() =>
            [.. typeof(PasswordGeneratorController).Assembly
                .GetTypes()
                .Where(type => type.IsClass
                    && !type.IsAbstract
                    && typeof(ControllerBase).IsAssignableFrom(type))
                .OrderBy(type => type.Name, StringComparer.Ordinal)];

        /// <summary>
        /// A controller that asks for a service the API does not register, used only to prove the
        /// activation check reports a failure when there is one.
        /// </summary>
        /// <remarks>
        /// Deliberately nested and private so it is not discovered as a real controller, and it is
        /// excluded from <see cref="Controllers"/> because that reflects over the API assembly, not this
        /// test assembly.
        /// </remarks>
        private sealed class UnregisteredDependencyController(IUnregisteredService service) : ControllerBase
        {
            /// <summary>Keeps the parameter used so the constructor cannot be optimised away.</summary>
            public IUnregisteredService Service { get; } = service;
        }

        /// <summary>A service intentionally never registered anywhere.</summary>
        public interface IUnregisteredService
        {
        }
    }
}
