using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Mockporten.Configuration;
using Mockporten.Services;
using Mockporten.Services.Interfaces;
using Mockporten.Services.Implementation;
using Xunit;

namespace Mockporten.Tests
{
    /// <summary>
    /// The JWT-bearer grant (RFC 7523) must only mint tokens for registered clients whose grant is
    /// signed by the registered key, addressed to this issuer, and within the client's allowed scopes.
    /// </summary>
    public class TokenServiceJwtGrantTests
    {
        private const string Issuer = "https://test-idp.example/";
        private const string ClientId = "synthetic-client";

        private static readonly RSA ClientKey = RSA.Create(2048);

        private sealed class StaticCertificateProvider : IJwtSigningCertificateProvider
        {
            private readonly X509Certificate2 _cert;

            public StaticCertificateProvider()
            {
                using RSA rsa = RSA.Create(2048);
                CertificateRequest req = new("CN=mockporten-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            }

            public Task<List<X509Certificate2>> GetCertificates() => Task.FromResult(new List<X509Certificate2> { _cert });
        }

        private static TokenService NewService(bool enabled = true, params string[] allowedScopes) =>
            NewService(2, enabled, allowedScopes);

        private static TokenService NewService(int validityMinutes, bool enabled, params string[] allowedScopes)
        {
            MaskinportenSettings settings = new()
            {
                Enabled = enabled,
                Clients =
                {
                    new MaskinportenClient
                    {
                        ClientId = ClientId,
                        OrgNo = "991825827",
                        PublicJwk = JsonWebKeySerializer(),
                        AllowedScopes = new List<string>(allowedScopes),
                    },
                },
            };

            return new TokenService(
                Options.Create(new GeneralSettings
                {
                    IdProviderEndpoint = Issuer,
                    IssToken = Issuer + "authorization",
                    JwtValidityMinutes = validityMinutes,
                }),
                Options.Create(settings),
                new StaticCertificateProvider(),
                NullLogger<TokenService>.Instance);
        }

        private static string JsonWebKeySerializer()
        {
            RsaSecurityKey key = new(ClientKey.ExportParameters(false));
            JsonWebKey jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            return System.Text.Json.JsonSerializer.Serialize(new { kty = jwk.Kty, n = jwk.N, e = jwk.E });
        }

        private static string Grant(
            string scope,
            RSA? signWith = null,
            string audience = Issuer,
            string issuer = ClientId,
            string algorithm = SecurityAlgorithms.RsaSha256,
            string? jti = null)
        {
            SigningCredentials creds = new(new RsaSecurityKey(signWith ?? ClientKey), algorithm);
            List<Claim> claims = new() { new Claim("scope", scope) };
            if (jti != string.Empty)
            {
                claims.Add(new Claim("jti", jti ?? Guid.NewGuid().ToString()));
            }

            JwtSecurityToken token = new(
                issuer,
                audience,
                claims,
                DateTime.UtcNow.AddSeconds(-5),
                DateTime.UtcNow.AddSeconds(60),
                creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [Fact]
        public async Task Disabled_IsRejectedAsUnsupportedGrantType()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService(enabled: false).GetTokenFromJwtGrant(Grant("altinn:serviceowner")));

            Assert.Equal("unsupported_grant_type", ex.Error);
        }

        [Fact]
        public async Task UnknownClient_IsRejected()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService().GetTokenFromJwtGrant(Grant("altinn:serviceowner", issuer: "someone-else")));

            Assert.Equal("invalid_client", ex.Error);
        }

        [Fact]
        public async Task WrongSigningKey_IsRejected()
        {
            using RSA other = RSA.Create(2048);

            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService().GetTokenFromJwtGrant(Grant("altinn:serviceowner", signWith: other)));

            Assert.Equal("invalid_grant", ex.Error);
        }

        [Fact]
        public async Task WrongAudience_IsRejected()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService().GetTokenFromJwtGrant(Grant("altinn:serviceowner", audience: "https://other.example/")));

            Assert.Equal("invalid_grant", ex.Error);
        }

        [Fact]
        public async Task ScopeOutsideAllowList_IsRejected()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService(true, "altinn:serviceowner").GetTokenFromJwtGrant(Grant("altinn:serviceowner altinn:admin")));

            Assert.Equal("invalid_scope", ex.Error);
        }

        [Fact]
        public async Task EmptyAllowList_RejectsEveryScope()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService().GetTokenFromJwtGrant(Grant("altinn:serviceowner")));

            Assert.Equal("invalid_scope", ex.Error);
        }

        [Fact]
        public async Task NoScope_IsRejected()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService(true, "altinn:serviceowner").GetTokenFromJwtGrant(Grant(string.Empty)));

            Assert.Equal("invalid_scope", ex.Error);
        }

        [Fact]
        public async Task NonRs256Algorithm_IsRejected()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService(true, "altinn:serviceowner")
                    .GetTokenFromJwtGrant(Grant("altinn:serviceowner", algorithm: SecurityAlgorithms.RsaSsaPssSha256)));

            Assert.Equal("invalid_grant", ex.Error);
        }

        [Fact]
        public async Task MissingJti_IsRejected()
        {
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => NewService(true, "altinn:serviceowner").GetTokenFromJwtGrant(Grant("altinn:serviceowner", jti: string.Empty)));

            Assert.Equal("invalid_grant", ex.Error);
        }

        [Fact]
        public async Task ReplayedAssertion_IsRejected()
        {
            TokenService service = NewService(true, "altinn:serviceowner");
            string assertion = Grant("altinn:serviceowner");

            await service.GetTokenFromJwtGrant(assertion);
            OidcRequestException ex = await Assert.ThrowsAsync<OidcRequestException>(
                () => service.GetTokenFromJwtGrant(assertion));

            Assert.Equal("invalid_grant", ex.Error);
        }

        [Fact]
        public async Task UnsetValidity_FallsBackToOidcAccessTokenLifetime()
        {
            (string token, _, int expiresIn) = await NewService(0, true, "altinn:serviceowner")
                .GetTokenFromJwtGrant(Grant("altinn:serviceowner"));

            JwtSecurityToken parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
            Assert.Equal(TokenService.AccessTokenLifetimeMinutes * 60, expiresIn);
            Assert.True(parsed.ValidTo > DateTime.UtcNow.AddMinutes(TokenService.AccessTokenLifetimeMinutes - 1));
        }

        [Fact]
        public async Task ValidGrant_MintsMaskinportenStyleToken()
        {
            (string token, string scope, int expiresIn) = await NewService(true, "altinn:serviceowner")
                .GetTokenFromJwtGrant(Grant("altinn:serviceowner"));

            JwtSecurityToken parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
            Assert.Equal("altinn:serviceowner", scope);
            Assert.Equal(120, expiresIn);
            Assert.Equal(Issuer, parsed.Issuer);
            Assert.Equal(ClientId, parsed.Payload["client_id"]);
            Assert.Contains("0192:991825827", parsed.Payload["consumer"].ToString());
        }
    }
}
