namespace TodoApi
{
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.OneIM.SSO.SigningCertificatesProvider;
    using System;
    using System.Linq;
    using System.Security.Claims;

    public class IcmJwtAuthenticationConfiguration
    {
        public const string AuthenticationScheme = "Bearer";

        /// <summary> Gets or sets a collection of valid issuers </summary>
        public string[] ValidIssuers { get; set; }
        /// <summary> Gets or sets a collection of valid audiences </summary>
        public string[] ValidAudiences { get; set; }
        /// <summary>Gets or sets the url pointing to the SSO endpoint that will return certificates.</summary>
        public string MetadataAddress { get; set; }
        /// <summary>Gets or sets the refresh frequency in minutes that the SigningCertificateProvider will check for new certs from <see cref="MetadataAddress" /></summary>
        public int MetadataRefreshFrequencyInMinutes { get; set; }
        /// <summary> Gets or sets the map of recognized upn claim types </summary>
        public string[] UpnClaimTypes { get; set; }
        /// <summary>Throws if not valid</summary>
        public void ThrowIfNotValid()
        {
            Action<string[], string> validateList = (list, name) =>
            {
                if (list == null || list.Length == 0)
                {
                    throw new ArgumentException($"Token validation configuration is invalid. Missing parameter: {name}");
                }
            };
            validateList(this.ValidIssuers, "Valid Issuers");
            validateList(this.ValidAudiences, "Valid Audiences");
            validateList(this.UpnClaimTypes, "Upn Claim Types");
            if (string.IsNullOrEmpty(this.MetadataAddress))
            {
                throw new ArgumentException("Metadata address is required");
            }
            if (MetadataRefreshFrequencyInMinutes <= 0)
            {
                throw new ArgumentException("Metadata refresh frequency is required");
            }
        }
        /// <summary>Creates JSON web token validation parameters for IcM JWT tokens</summary>
        /// <returns>token validation parameters</returns>
        public TokenValidationParameters ToTokenValidationParameters()
        {
            ISigningCertificatesProvider ssoCertProvider = SigningCertificatesProviderFactory.CreateSigningCertificateProviderForIcmPartner(
                certificateAddress: this.MetadataAddress,
                certificateRefreshFrequencyInMinutes: this.MetadataRefreshFrequencyInMinutes);
            return new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                ValidateIssuer = true,
                ValidateAudience = true,                
                ValidIssuers = this.ValidIssuers,
                ValidAudiences = this.ValidAudiences,
                IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                    ssoCertProvider
                        .GetSigningCertificates()
                        .GetAwaiter()
                        .GetResult()
                        .Select(x => new X509SecurityKey(x)),
            };
        }
        /// <summary>Extracts the UPN from the claims</summary>
        /// <param name="claims">user claims</param>
        /// <returns>the UPN of the user</returns>
        /// <exception cref="InvalidOperationException">if no UPN found</exception>
        public string ExtractUpn(Claim[] claims)
        {
            foreach (string upnClaimType in this.UpnClaimTypes)
            {
                Claim? upnClaim = claims.FirstOrDefault(o => o.Type.Equals(upnClaimType, StringComparison.OrdinalIgnoreCase));
                if (upnClaim != null)
                {
                    return upnClaim.Value.Trim();
                }
            }
            throw new InvalidOperationException("No UPN found in token");
        }
    }
}
