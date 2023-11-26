using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AngularAuthAPI.Exceptions
{
    public class AppExceptionHandler : IExceptionHandler
    {
        private readonly ILogger _logger;
        public AppExceptionHandler(ILogger logger)
        {
            _logger = logger;
        }


        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            (int statusCode, string errorMessage) = exception switch
            {
                //StatusCodes.Status403Forbidden
                //StatusCodes.Status403Forbidden => (403, "Forbidden")
                ForbideException => (403, ""),
                BadRequestException badR => (400, badR.Message),
                NotFoundException notFound=> (404, notFound.Message),
                _=> default
            };

            if(statusCode == default)
            {
                return false;  // will continue to find 2nd resgisterd exception handler.
            }

            _logger.LogError(errorMessage);
            httpContext.Response.StatusCode = statusCode;
            await httpContext.Response.WriteAsJsonAsync(errorMessage);

            return  true;
            // or : return await ValueTask.FromResult(false);

        }
    }
}
