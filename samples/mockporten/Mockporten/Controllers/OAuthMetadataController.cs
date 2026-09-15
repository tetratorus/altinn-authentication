using Mockporten.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Mockporten.Controllers
{
    /// <summary>
    /// RFC 8414 authorization-server metadata, published where Maskinporten clients look for it
    /// (<c>{authority}/.well-known/oauth-authorization-server</c>).
    /// </summary>
    [Route("/.well-known/oauth-authorization-server")]
    [AllowAnonymous]
    [ApiController]
    public class OAuthMetadataController : ControllerBase
    {
        private readonly GeneralSettings _generalSettings;

        public OAuthMetadataController(IOptions<GeneralSettings> generalSettings)
        {
            _generalSettings = generalSettings.Value;
        }

        [HttpGet]
        [Produces("application/json")]
        public IActionResult Get()
        {
            string root = _generalSettings.IdProviderEndpoint.TrimEnd('/') + "/";
            return Ok(new
            {
                issuer = root,
                token_endpoint = root + "token",
                jwks_uri = root + "api/v1/openid/.well-known/openid-configuration/jwks",
                grant_types_supported = new[] { "authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                token_endpoint_auth_methods_supported = new[] { "private_key_jwt" },
                token_endpoint_auth_signing_alg_values_supported = new[] { "RS256" },
            });
        }
    }
}
