using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public class OAuth2Convert
    {
        public const string GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
        public const string GRANT_TYPE_IMPLICIT = "implicit";
        public const string GRANT_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS = "password";
        public const string GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
        public const string GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

        public const string RESPONSE_TYPE_CODE = "code";
        public const string RESPONSE_TYPE_TOKEN = "token";

        public const string TOKEN_ENDPOINT_NONE = "none";
        public const string TOKEN_ENDPOINT_CLIENT_SECRET_BASIC = "client_secret_basic";
        public const string TOKEN_ENDPOINT_CLIENT_SECRET_POST = "client_secret_post";

        public static string ConvertGrantTypeToString(OAuth2GrantType value)
        {
            switch (value)
            {
                case OAuth2GrantType.AuthorizationCode:
                    return GRANT_TYPE_AUTHORIZATION_CODE;
                case OAuth2GrantType.ClientCredentials:
                    return GRANT_TYPE_CLIENT_CREDENTIALS;
                case OAuth2GrantType.Implicit:
                    return GRANT_TYPE_IMPLICIT;
                case OAuth2GrantType.Password:
                    return GRANT_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS;
                case OAuth2GrantType.RefreshToken:
                    return GRANT_TYPE_REFRESH_TOKEN;
                default:
                    return null;
            }
        }
        public static OAuth2GrantType? ConvertStringToGrantType(string value)
        {
            switch (value.ToLowerInvariant())
            {
                case GRANT_TYPE_AUTHORIZATION_CODE:
                    return OAuth2GrantType.AuthorizationCode;
                case GRANT_TYPE_CLIENT_CREDENTIALS:
                    return OAuth2GrantType.ClientCredentials;
                case GRANT_TYPE_IMPLICIT:
                    return OAuth2GrantType.Implicit;
                case GRANT_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS:
                    return OAuth2GrantType.Password;
                case GRANT_TYPE_REFRESH_TOKEN:
                    return OAuth2GrantType.RefreshToken;
                default:
                    return null;
            }
        }

        public static string ConvertResponseTypeToString(OAuth2ResponseType value)
        {
            switch (value)
            {
                case OAuth2ResponseType.Code:
                    return RESPONSE_TYPE_CODE;
                case OAuth2ResponseType.Token:
                    return RESPONSE_TYPE_TOKEN;
                default:
                    return null;
            }
        }

        public static OAuth2ResponseType? ConvertStringToResponseType(string value)
        {
            switch (value)
            {
                case RESPONSE_TYPE_CODE:
                    return OAuth2ResponseType.Code;
                case RESPONSE_TYPE_TOKEN:
                    return OAuth2ResponseType.Token;
                default:
                    return null;
            }
        }

        public static string ConvertTokenEndpointAuthMethodToString(OAuth2TokenEndpointAuthMethod value)
        {
            switch (value)
            {
                case OAuth2TokenEndpointAuthMethod.None:
                    return TOKEN_ENDPOINT_NONE;
                case OAuth2TokenEndpointAuthMethod.ClientSecretBasic:
                    return TOKEN_ENDPOINT_CLIENT_SECRET_BASIC;
                case OAuth2TokenEndpointAuthMethod.ClientSecretPost:
                    return TOKEN_ENDPOINT_CLIENT_SECRET_POST;
                default:
                    return null;
            }
        }

        public static OAuth2TokenEndpointAuthMethod? ConvertStringToTokenEndpointAuthMethod(string value)
        {
            switch (value)
            {
                case TOKEN_ENDPOINT_NONE:
                    return OAuth2TokenEndpointAuthMethod.None;
                case TOKEN_ENDPOINT_CLIENT_SECRET_BASIC:
                    return OAuth2TokenEndpointAuthMethod.ClientSecretBasic;
                case TOKEN_ENDPOINT_CLIENT_SECRET_POST:
                    return OAuth2TokenEndpointAuthMethod.ClientSecretPost;
                default:
                    return null;
            }
        }
    }
}
