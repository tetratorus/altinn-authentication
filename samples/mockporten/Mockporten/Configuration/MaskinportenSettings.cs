using System.Collections.Generic;

namespace Mockporten.Configuration
{
    /// <summary>
    /// Machine clients allowed to obtain Maskinporten-style tokens through the JWT-bearer grant.
    /// Each client authenticates with a JWT grant signed by the private key matching <see cref="MaskinportenClient.PublicJwk"/>.
    /// </summary>
    public class MaskinportenSettings
    {
        /// <summary>Whether the JWT-bearer grant is accepted at all.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>Registered clients.</summary>
        public List<MaskinportenClient> Clients { get; set; } = new();
    }

    /// <summary>A registered Maskinporten client.</summary>
    public class MaskinportenClient
    {
        /// <summary>The client_id, used as the <c>iss</c> of the JWT grant.</summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>Organisation number of the consumer the token is issued to.</summary>
        public string OrgNo { get; set; } = string.Empty;

        /// <summary>Public RSA JSON Web Key (JWK JSON) used to verify the grant signature.</summary>
        public string PublicJwk { get; set; } = string.Empty;

        /// <summary>Scopes this client may request. A grant requesting a scope outside this list, or no scope at all, is rejected.</summary>
        public List<string> AllowedScopes { get; set; } = new();
    }
}
