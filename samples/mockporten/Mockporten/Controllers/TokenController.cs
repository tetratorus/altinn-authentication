using Mockporten.Configuration;
using Mockporten.Models;
using Mockporten.Services;
using Mockporten.Services.Implementation;
using Mockporten.Services.Interface;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Threading.Tasks;

namespace Mockporten.Controllers
{
    [Route("token")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IToken _tokenService;
        private readonly GeneralSettings _generalSettings;

        public TokenController(IToken tokenService, IOptions<GeneralSettings> generalSettings)
        {
            _tokenService = tokenService;
            _generalSettings = generalSettings.Value;
        }

        [Consumes("application/x-www-form-urlencoded")]
        [HttpPost]
        public async Task<ActionResult> Index(
            [FromForm] string client_id, 
            [FromForm] string grant_type, 
            [FromForm] string code, 
            [FromForm] string redirect_uri,
            [FromForm] string code_verifier,
            [FromForm] string client_assertion_type,
            [FromForm] string client_assertion,
            [FromForm] string assertion,
            [FromForm] string refresh_token)
        {
            if (!_generalSettings.TestIdpEnabled)
            {
                return NotFound();
            }

            if (string.Equals(grant_type, "urn:ietf:params:oauth:grant-type:jwt-bearer", StringComparison.Ordinal))
            {
                try
                {
                    (string accessToken, string scope, int expiresIn) = await _tokenService.GetTokenFromJwtGrant(assertion);
                    return Ok(new
                    {
                        access_token = accessToken,
                        token_type = "Bearer",
                        expires_in = expiresIn,
                        scope,
                    });
                }
                catch (OidcRequestException ex)
                {
                    return BadRequest(new { error = ex.Error, error_description = ex.Message });
                }
            }

            if (!string.Equals(grant_type, "authorization_code", StringComparison.Ordinal))
            {
                return BadRequest(new { error = "unsupported_grant_type", error_description = "Only authorization_code and jwt-bearer are supported" });
            }

            string token;
            try
            {
                token = await _tokenService.GetTokenFromCode(code, code_verifier);
            }
            catch (OidcRequestException ex)
            {
                return BadRequest(new { error = ex.Error, error_description = ex.Message });
            }

            GrantResponse grantResponse = new GrantResponse
            {
                id_token = token,
                access_token = token,
                token_type = "Bearer",
                expires_in = TokenService.AccessTokenLifetimeMinutes * 60,
                refresh_token = Guid.NewGuid().ToString("N")
            };
            return Ok(grantResponse);
        }
    }
}
