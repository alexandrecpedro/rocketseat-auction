using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.VisualBasic.FileIO;
using RocketseatAuction.API.Contracts;

namespace RocketseatAuction.API.Filters;

public class AuthenticationUserAttribute : AuthorizeAttribute, IAuthorizationFilter
{
    private IUserRepository _repository;

    public AuthenticationUserAttribute(IUserRepository repository) => _repository = repository;
    
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        try
        {
            var token = TokenOnRequest(context.HttpContext);

            var email = FromBase64String(token);

            var userExists = _repository.ExistUserWithEmail(email);

            if (!userExists)
            {
                context.Result = new UnauthorizedObjectResult("Invalid email/password!");
            }
        }
        catch (Exception e)
        {
            context.Result = new UnauthorizedObjectResult(e.Message);
        }
    }

    private string TokenOnRequest(HttpContext context)
    {
        var authentication = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(authentication))
        {
            throw new MalformedLineException("Malformed token!");
        }

        return authentication["Bearer ".Length..];
    }

    private string FromBase64String(string base64)
    {
        var data = Convert.FromBase64String(base64);

        return System.Text.Encoding.UTF8.GetString(data);
    }
}