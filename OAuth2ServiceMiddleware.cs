using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Strombus.Redis;
using Strombus.ServerShared;
using Microsoft.AspNetCore.Builder;
using Strombus.OAuth2Service.OAuth2;
using Newtonsoft.Json;
using System.Text;
using System.Net;
using System.Reflection;
using System.IO;
using Strombus.OAuth2.Server;

namespace Strombus.OAuth2Service
{
    public class OAuth2ServiceMiddleware
    {
        private readonly RequestDelegate _next;

        private const string APIPATH_OAUTH2 = "oauth2";
        private const string APIPATH_CLIENT_REGISTRATION = "register";
        private const string APIPATH_AUTHORIZATION = "authorize";
        private const string APIPATH_TOKEN = "token";
        private const string APIPATH_REDIRECT = "redirect";

        // authorization code timeout
        private const long AUTHORIZATION_CODE_TIMEOUT_SECONDS = 60;

        // dynamic client registration endpoint errors
        private const string ERROR_INVALID_CLIENT_METADATA = "invalid_client_metadata";
        private const string ERROR_INVALID_REDIRECT_URI = "invalid_redirect_uri";
        // authorization+token endpoint errors
        private const string ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";
        private const string ERROR_INVALID_SCOPE = "invalid_scope";
        //    private const string ERROR_SERVER_ERROR = "server_error";
        //    private const string ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
        // authorization endpoint errors
        private const string ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
        private const string ERROR_ACCESS_DENIED = "access_denied";
        // token endpoint errors
        private const string ERROR_INVALID_REQUEST = "invalid_request";
        private const string ERROR_INVALID_CLIENT = "invalid_client";
        private const string ERROR_INVALID_GRANT = "invalid_grant";
        private const string ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

        private const int MAX_PAYLOAD_SIZE_CLIENT_REGISTRATION = 4096;

        private const string REDIS_PREFIX_HIGHTRUST_SERVICE_CLIENTS = "hightrust-service-clients";
        private const string REDIS_PREFIX_SEPARATOR = ":";
        //
        private const string REDIS_SLASH = "/";

        private const string LOGIN_SERVICE_NAME = "login";

        private RedisClient _redisClient;

        public OAuth2ServiceMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            // ensure that we have a connection to the Redis server
            // NOTE: we could do this in our constructor, but we have intentionally avoided putting any code there which could block or throw an exception.  Instead we lazily load the redis client here.
            if (_redisClient == null)
            {
                // NOTE: this call will attempt to create the connection if it does not already exists (and will "block" in an async-friendly fashion)
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            // process non-websocket HTTP requests
            if (context.WebSockets.IsWebSocketRequest == false)
            {
                string path = context.Request.Path.ToString();
                List<string> pathHierarchy = new List<string>(path.Split(new char[] { '/' }));
                // if the last entry is a forward-slash, remove it now; the trailing forward-slash is optional and should be ignored
                if (pathHierarchy.Count > 0 && pathHierarchy[pathHierarchy.Count - 1] == string.Empty)
                {
                    pathHierarchy.RemoveAt(pathHierarchy.Count - 1);
                }
                int pathHierarchyLength = pathHierarchy.Count;
                int pathHierarchyIndex = 0;

                // process the path
                /* THE RULES:
                 * the service must be the first element in the path (/oauth2); because the first character will be '/', the element will be at index 1.
                 * the order of the remaining path elements determines the meaning of the path
                 * example: /oauth2/register means "register client" (or query all registered clients), whereas
                 *          /oauth2/register/{oauth2client_id} means manage/get info for that registered client.
                */

                /* VALID PATH OPTIONS: (+ for implemented, - for not yet implemented)
                 * + /oauth2/authorize
                 * - /oauth2/redirect
                 * + /oauth2/register
                 * - /oauth2/register/{client_id}
                 * + /oauth2/token
                */

                bool isOAuth2Url = false;
                if (pathHierarchyLength >= 2 && pathHierarchy[0] == "")
                {
                    switch (pathHierarchy[1].ToLowerInvariant())
                    {
                        case APIPATH_OAUTH2:
                            isOAuth2Url = true;
                            pathHierarchyIndex += 2;
                            break;
                        default:
                            isOAuth2Url = false;
                            break;
                    }
                }
                if (isOAuth2Url == false)
                {
                    // non-oauth2 call
                }
                else
                {
                    // first, verify that the hostname specifies our service (and extract the accountId and serverId, if specified) in the process
                    string accountId, serverId;
                    var hostnameExtractionResults = ExtractAccountIdAndServerIdFromHostname(context.Request.Headers["Host"], LOGIN_SERVICE_NAME);
                    if (hostnameExtractionResults != null)
                    {
                        // extract the accountId and serverId from the hostname
                        accountId = hostnameExtractionResults.Value.AccountId;
                        serverId = hostnameExtractionResults.Value.ServerId;

                        // determine the request type from the remainder of the hierarchy
                        int pathHierarchyElementsRemaining = pathHierarchyLength - pathHierarchyIndex;

                        if (pathHierarchyElementsRemaining == 1 && pathHierarchy[pathHierarchyIndex + 0].ToLowerInvariant() == APIPATH_CLIENT_REGISTRATION)
                        {
                            // PATH: /oauth2/register
                            string[] supportedMethods = new string[] { "POST" };
                            switch (context.Request.Method.ToUpperInvariant())
                            {
                                case "OPTIONS":
                                    HttpHelper.SetHttpResponseNoContent_ForOptionsMethod(context, supportedMethods);
                                    return;
                                case "POST":
                                    await RegisterClientAsync(context, accountId, serverId).ConfigureAwait(false);
                                    return;
                                default:
                                    HttpHelper.SetHttpResponseMethodNotAllowed(context, supportedMethods);
                                    return;
                            }
                        }
                        else if (pathHierarchyElementsRemaining == 1 && pathHierarchy[pathHierarchyIndex + 0].ToLowerInvariant() == APIPATH_AUTHORIZATION)
                        {
                            // PATH: /oauth2/authorize
                            string[] supportedMethods = new string[] { "GET", "POST" };
                            switch (context.Request.Method.ToUpperInvariant())
                            {
                                case "OPTIONS":
                                    HttpHelper.SetHttpResponseNoContent_ForOptionsMethod(context, supportedMethods);
                                    return;
                                case "GET":  // request login page
                                case "POST": // submit username/password credentials
                                    await AuthorizeClientAsync(context).ConfigureAwait(false);
                                    return;
                                default:
                                    HttpHelper.SetHttpResponseMethodNotAllowed(context, supportedMethods);
                                    return;
                            }
                        }
                        else if (pathHierarchyElementsRemaining == 1 && pathHierarchy[pathHierarchyIndex + 0].ToLowerInvariant() == APIPATH_TOKEN)
                        {
                            // PATH: /oauth2/token
                            string[] supportedMethods = new string[] { "POST" };
                            switch (context.Request.Method.ToUpperInvariant())
                            {
                                case "OPTIONS":
                                    HttpHelper.SetHttpResponseNoContent_ForOptionsMethod(context, supportedMethods);
                                    return;
                                case "POST":
                                    await IssueTokenAsync(context).ConfigureAwait(false);
                                    return;
                                default:
                                    HttpHelper.SetHttpResponseMethodNotAllowed(context, supportedMethods);
                                    return;
                            }
                        }
                        else if (pathHierarchyElementsRemaining == 2 && pathHierarchy[pathHierarchyIndex + 0].ToLowerInvariant() == APIPATH_TOKEN &&
                                                                        pathHierarchy[pathHierarchyIndex + 1] != string.Empty)
                        {
                            // PATH: /oauth2/token/{token_id}
                            string tokenId = pathHierarchy[pathHierarchyIndex + 1];
                            //
                            string[] supportedMethods = new string[] { "GET" };
                            switch (context.Request.Method.ToUpperInvariant())
                            {
                                case "OPTIONS":
                                    HttpHelper.SetHttpResponseNoContent_ForOptionsMethod(context, supportedMethods);
                                    return;
                                case "GET":
                                    await GetTokenAsync(context, tokenId).ConfigureAwait(false);
                                    return;
                                default:
                                    HttpHelper.SetHttpResponseMethodNotAllowed(context, supportedMethods);
                                    return;
                            }
                        }
                        else if (pathHierarchyElementsRemaining == 1 && pathHierarchy[pathHierarchyIndex + 0].ToLowerInvariant() == APIPATH_REDIRECT)
                        {
                            // PATH: /oauth2/redirect
                            string[] supportedMethods = new string[] { "GET" };
                            switch (context.Request.Method.ToUpperInvariant())
                            {
                                case "OPTIONS":
                                    HttpHelper.SetHttpResponseNoContent_ForOptionsMethod(context, supportedMethods);
                                    return;
                                case "GET":
                                    await ProcessRedirectEndpointAsync(context).ConfigureAwait(false);
                                    return;
                                default:
                                    HttpHelper.SetHttpResponseMethodNotAllowed(context, supportedMethods);
                                    return;
                            }
                        }
                        // else if...
                    }
                }
            }

            await _next(context).ConfigureAwait(false);
        }

        private struct ExtractAccountIdAndServerIdFromHostnameResult
        {
            public string AccountId; // if null, root server; otherwise this is an account-specific server
            public string ServerId;  // this will return the specified server-id (if one was specified)
        }
        private ExtractAccountIdAndServerIdFromHostnameResult? ExtractAccountIdAndServerIdFromHostname(string hostname, string serviceName)
        {
            string accountId;
            string serverId;

            // convert the serviceName to lower-case for our comparisons
            serviceName = serviceName.ToLowerInvariant();

            if (hostname == null || hostname.IndexOf("-") == 0 || hostname.IndexOf(".") == 0)
            {
                // hostname does not exist (or started with a hyphen or period); therefore hostname is not valid
                return null;
            }

            // hostname exists; try to extract the accountname if one was provided
            if (hostname.ToLowerInvariant().IndexOf(serviceName + ".") == 0 || hostname.ToLowerInvariant().IndexOf(serviceName + "-") == 0)
            {
                // the hostname specifies a root server for this service
                accountId = null;
            }
            else 
            {
                // hostname begins with "accountname-"; extract the account name
                accountId = hostname.Substring(0, hostname.IndexOf("-"));
                // remove the "accountname-" prefix from the hostname
                hostname = hostname.Substring(hostname.IndexOf("-") + 1);
            }

            // now, validate the remaining hostname to extract the server #, if any (and simultaneously validate that the hostname belongs to this service)
            if (hostname.ToLowerInvariant().IndexOf(serviceName + ".") == 0)
            {
                // service name matches; there is no specific server #
                serverId = null;
            }
            else if (hostname.ToLowerInvariant().IndexOf(serviceName + "-") == 0)
            {
                // service name matches; there is a specific server #

                // remove the "servicename-" prefix from the hostname
                hostname = hostname.ToLowerInvariant().Substring(hostname.IndexOf("-") + 1);

                // verify that the serverId is not empty (and does not start with a disallowed character)
                if (hostname.IndexOf(".") == 0 || hostname.IndexOf("-") == 0)
                {
                    // hostname is invalid
                    return null;
                }

                // finally, now that we have not rejected the hostname: parse our the server-id
                serverId = hostname.Substring(0, hostname.IndexOf("."));
            }
            else
            {
                // we could not locate the service name in our hostname
                return null;
            }

            // at this point, we know that the hostname is syntactically valid

            // return our accountId and serverId
            return new ExtractAccountIdAndServerIdFromHostnameResult()
            {
                AccountId = accountId,
                ServerId = serverId
            };
        }

        #region REGISTRATION API

        private struct RegisterClientRequest
        {
            public string software_id;
            public string software_version;
            public string[] redirect_uris;
            public string token_endpoint_auth_method;
            public string[] grant_types;
            public string[] response_types;
            public string scope;
        }
        private struct RegisterClientResponse
        {
            public string client_id;
            public string client_secret;
            public long? client_id_issued_at;
            public long? client_secret_expires_at;
            public string software_id;
            public string software_version;
            public string[] redirect_uris;
            public string token_endpoint_auth_method;
            public string[] grant_types;
            public string[] response_types;
            public string scope;
            public string registration_access_token;
            public string registration_client_uri;
        }
        private async Task RegisterClientAsync(HttpContext context, string accountId, string serverId)
        {
            /* NOTES:
             * This function registers a client with the Strombus cloud.
             * 
             * Three registration options:
             * 1. Any app: pass in the software_id and use its software initial_access_token (widely-distributed with app) as Authorization bearer token.  This will permit the use of Authorization Code, Implicit and Refresh Token grant types.
             *    NOTE: first-party apps may be trust-upgraded to allow "resource owner password" grant type after initial registration for authorization code grant type.  See internal documentation for details.
             * 2. Server apps: pass in a server initial_access_token (known only to server owner) as Authorization bearer token.  This will permit the use of the Client Credentials code flow.
             *    NOTE: server-to-server apps may be restricted to registration through the Strombus web console.  TBD.
             * 3. In-app "start chat" feature and public clients which auto-login with restricted permissions: pass in the software_id and software initial_access_token (widely distributed with app) as Authorization bearer token.  This will permit the Implicit grant flow and limited scope of access.
             *    NOTE: if desired (although not recommended), a limited set of public clients may share the same client_id; in those cirumstances it really does not matter if clients register here...they can just skip to the OAuth Token endpoint.
             *
             * NOTE: this function is an OAuth2 Client Registration endpoint, compliant with the OAuth2 Dynamic Client Registration protocol (RFC7591).
             */

            if (await HttpHelper.VerifyContentTypeHeaderIsJson(context).ConfigureAwait(false) == false)
                return;
            if (await HttpHelper.VerifyAcceptHeaderIsJson(context).ConfigureAwait(false) == false)
                return;

            // verify that our server acts as a server for the specific accountId (or as a root server, if no accountId was specified)
            var verifyAccountResult = await RedisHelper.VerifyAccountIdAndServerIdAsync(_redisClient, LOGIN_SERVICE_NAME, accountId, true, serverId != null ? int.Parse(serverId) : (int?)null);
            if (verifyAccountResult.Success == false)
            {
                /* redirect to the root LOGIN server "https://login.example.com" instead */
                // NOTE: we use a permanent redirect here, as all scenarios where our server is being called with an invalid accountId/serverId is a permanent failure
                HttpHelper.SetHttpResponsePermanentRedirect(context, ParsingHelper.RewriteUrlWithServiceHostname(context, LOGIN_SERVICE_NAME, accountId));
                return;
            }
            // if our serverId was not specified and we were assigned a defaultServerId, then retrieve that now
            if (serverId == null)
            {
                serverId = verifyAccountResult.ServerId.Value.ToString();
            }

            // retrieve our bearer token (i.e. initial access token)
            var tokenId = HttpHelper.ExtractBearerTokenFromAuthorizationHeaderValue(context.Request.Headers["Authorization"]);
            if (tokenId != null && tokenId.Trim() == string.Empty)
            {
                tokenId = null;
            }
            if (tokenId == null)
            {
                // if no token was provided, fail immediately and let the client know that they MUST supply an initial access token.
                HttpHelper.SetHttpResponseUnauthorized(context);
                return;
            }
            // attempt to retrieve the token locally
            var oauth2InitialAccessToken = await OAuth2InitialAccessToken.LoadInitialAccessTokenAsync(tokenId, OAuth2InitialAccessToken.LoadTokenOptions.LocalTokens /* | OAuth2InitialAccessToken.LoadTokenOptions.PeerTokens */);
            //bool requestMustBeForwarded = false;
            if (oauth2InitialAccessToken == null)
            {
                bool tokenDoesNotExist = true; // set this to true if the token serverId is in our peer group but was not found
                if (tokenDoesNotExist)
                {
                    HttpHelper.SetHttpResponseForbidden(context);
                    return;
                }
            }
            // if initialAccessToken is null (i.e. null or not the correct type of token) then we should fail immediately.
            if (oauth2InitialAccessToken == null)
            {
                HttpHelper.SetHttpResponseUnauthorized(context);
                return;
            }

            /* NOTE: we do not need to cache initial access tokens, so we do not subscribe to token change/revoke events. */

            // NOTE: we place a hard size limit on the request content; this is to protect the service from unreasonably-large attack frames (which could fill memory with a million redirect_uris, etc.)
            if (context.Request.ContentLength > MAX_PAYLOAD_SIZE_CLIENT_REGISTRATION)
            {
                HttpHelper.SetHttpResponsePayloadTooLarge(context);
                return;
            }

            // retrieve the request payload
            byte[] buffer = new byte[context.Request.ContentLength ?? 0];
            int bytesRead = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            // deserialize the (JSON) request payload
            RegisterClientRequest request;
            try
            {
                request = JsonConvert.DeserializeObject<RegisterClientRequest>(Encoding.UTF8.GetString(buffer, 0, bytesRead));
            }
            catch (JsonException)
            {
                // if the request was malformed, return a generic error.
                HttpHelper.SetHttpResponseBadRequest(context);
                return;
            }
            // parse and preliminarily-validate the request (and supplement with default values as necessary and appropriate)
            string softwareId = request.software_id;
            string softwareVersion = request.software_version;
            List<string> redirectUris = new List<string>(request.redirect_uris);
            OAuth2TokenEndpointAuthMethod tokenEndpointAuthMethod;
            if (request.token_endpoint_auth_method != null)
            {
                OAuth2TokenEndpointAuthMethod? tokenEndpointauthMethodToTest = OAuth2Convert.ConvertStringToTokenEndpointAuthMethod(request.token_endpoint_auth_method.ToLowerInvariant());
                if (tokenEndpointauthMethodToTest != null)
                {
                    tokenEndpointAuthMethod = tokenEndpointauthMethodToTest.Value;
                }
                else
                {
                    // if an invalid value was supplied, return immediately with an error.
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "token_endpoint_auth_method '" + request.token_endpoint_auth_method + "' is invalid.").ConfigureAwait(false);
                    return;
                }
            }
            else
            {
                tokenEndpointAuthMethod = OAuth2TokenEndpointAuthMethod.ClientSecretBasic; // default (if none is supplied)
            }
            List<OAuth2GrantType> grantTypes = new List<OAuth2GrantType>();
            if (request.grant_types != null)
            {
                foreach (string grantTypeAsString in request.grant_types)
                {
                    OAuth2GrantType? grantType = OAuth2Convert.ConvertStringToGrantType(grantTypeAsString.ToLowerInvariant());
                    if (grantType != null)
                    {
                        grantTypes.Add(grantType.Value);
                    }
                    else
                    {
                        // ignore unknown grant types
                    }
                }
            }
            if (grantTypes.Count == 0)
            {
                grantTypes.Add(OAuth2GrantType.AuthorizationCode); // default (if none are supplied)
            }
            List<OAuth2ResponseType> responseTypes = new List<OAuth2ResponseType>();
            if (request.response_types != null)
            {
                foreach (string responseTypeAsString in request.response_types)
                {
                    OAuth2ResponseType? responseType = OAuth2Convert.ConvertStringToResponseType(responseTypeAsString.ToLowerInvariant());
                    if (responseType != null)
                    {
                        responseTypes.Add(responseType.Value);
                    }
                }
            }
            if (responseTypes.Count == 0)
            {
                responseTypes.Add(OAuth2ResponseType.Code); // default (if none are supplied)
            }
            List<string> scopes = new List<string>();
            if (request.scope != null)
            {
                scopes = new List<string>(request.scope.Split(' '));
                int iScope = 0;
                do
                {
                    // remove any empty scopes (i.e. caused by extra whitespace)
                    if (scopes[iScope] == "")
                    {
                        scopes.RemoveAt(iScope);
                        continue;
                    }
                    // also remove any scope values which contain invalid identifiers
                    if (!FormattingHelper.ContainsOnlyAllowedIdentifierCharacters(scopes[iScope]))
                    {
                        scopes.RemoveAt(iScope);
                        continue;
                    }
                    iScope++;
                } while (iScope < scopes.Count);
            }

            // further validate the supplied data as OAuth2-valid
            // verify that a software_id was supplied and is either a valid GUID or otherwise is not empty and conforms to our token formatting requirements.
            bool softwareIdIsInvalid = false;
            string formattedSoftwareId = string.Empty;
            if (softwareId == null)
            {
                softwareIdIsInvalid = true;
            }
            if (FormattingHelper.ContainsGuid(softwareId))
            {
                formattedSoftwareId = FormattingHelper.FormatGuidAsSafeIdentifierGuid(softwareId);
            }
            else if (softwareId != string.Empty && FormattingHelper.ContainsOnlyAllowedIdentifierCharacters(softwareId.Trim()))
            {
                formattedSoftwareId = softwareId.Trim().ToUpperInvariant();
            }
            else
            {
                softwareIdIsInvalid = true;
            }
            if (softwareIdIsInvalid)
            {
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "software_id '" + softwareId + "' is invalid.").ConfigureAwait(false);
                return;
            }
            // software_version is optional; any value (or null) is acceptable
            // make sure that the redirectUris use HTTPS or a non-HTTP protocol (i.e. an app-specific protocol on a mobile device)
            // NOTE: redirectUris may also use HTTP--but only with localhost.
            if (redirectUris != null)
            {
                Uri uri;
                for (int iRedirectUri = 0; iRedirectUri < redirectUris.Count; iRedirectUri++)
                {
                    try
                    {
                        uri = new Uri(redirectUris[iRedirectUri]);
                    }
                    catch
                    {
                        await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_REDIRECT_URI, "request_uri '" + redirectUris[iRedirectUri] + "' is invalid.").ConfigureAwait(false);
                        return;
                    }
                    // HTTP scheme is okay as long as the server is localhost (i.e. communication is on the loopback interface).
                    if (uri.Scheme.ToLowerInvariant() == "http")
                    {
                        if (uri.Host != "127.0.0.1" && uri.Host != "::1" && uri.Host.ToLowerInvariant() != "localhost")
                        {
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_REDIRECT_URI, "request_uri '" + redirectUris[iRedirectUri] + "' must be secured with the https scheme.").ConfigureAwait(false);
                            return;
                        }
                    }
                    // HTTPS scheme is okay
                    else if (uri.Scheme.ToLowerInvariant() == "https")
                    {
                        // these are okay.
                    }
                    // custom app-specific schemes are okay
                    else // if (uri.Scheme.ToLowerInvariant() != "http" && uri.Scheme.ToLowerInvariant() != "https")
                    {
                        // these are okay.
                    }
                }
            }
            // tokenEndpointAuthMethod was already validated during parsing; if we are going to disallow otherwise-valid values, do so here.
            // verify that the requested grant_types and response_types are compatible
            // NOTE: grantType 'authorization_code' is the default, so if there are no grant types listed then 'authorization_code' is inferred.
            if (grantTypes.Contains(OAuth2GrantType.AuthorizationCode))
            {
                // NOTE: responseType 'code' is the default, so if there are no response types listed then 'code' is inferred.
                if (!responseTypes.Contains(OAuth2ResponseType.Code))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_AUTHORIZATION_CODE + "' requires response_type '" + OAuth2Convert.RESPONSE_TYPE_CODE + "'.").ConfigureAwait(false);
                    return;
                }
            }
            if (grantTypes.Contains(OAuth2GrantType.Implicit))
            {
                if (!responseTypes.Contains(OAuth2ResponseType.Token))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "' requires response_type '" + OAuth2Convert.RESPONSE_TYPE_TOKEN + "'.").ConfigureAwait(false);
                    return;
                }
            }
            // NOTE: responseType 'code' is the default, so if there are no response types listed then 'code' is inferred.
            if (responseTypes.Contains(OAuth2ResponseType.Code))
            {
                // NOTE: grantType 'authorization_code' is the default, so if there are no grant types listed then 'authorization_code' is inferred.
                if (!grantTypes.Contains(OAuth2GrantType.AuthorizationCode))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "response_type '" + OAuth2Convert.RESPONSE_TYPE_CODE + "' requires grant_type '" + OAuth2Convert.GRANT_TYPE_AUTHORIZATION_CODE + "'.").ConfigureAwait(false);
                    return;
                }
            }
            if (responseTypes.Contains(OAuth2ResponseType.Token))
            {
                if (!grantTypes.Contains(OAuth2GrantType.Implicit))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "response_type '" + OAuth2Convert.RESPONSE_TYPE_TOKEN + "' requires grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "'.").ConfigureAwait(false);
                    return;
                }
            }
            // if grant types require redirect_uris, make sure we include at least one redirect_uri.
            if (redirectUris == null || redirectUris.Count == 0)
            {
                if (grantTypes.Contains(OAuth2GrantType.Implicit))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "' requires one or more redirect_uris.").ConfigureAwait(false);
                    return;
                }
                if (grantTypes.Contains(OAuth2GrantType.AuthorizationCode))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_AUTHORIZATION_CODE + "' requires one or more redirect_uris.").ConfigureAwait(false);
                    return;
                }
            }
            /* our implementation of OAuth2 is restrictive, following "Security Considerations" noted in RFC 7591 section 5.
               as such, we only allow clients to register the following sets of grant types:
               - authorization_code (clients with permissions to authenticate their users via a web browser only--and which can secure a client secret)
               - authorization_code (public clients only able to authenticate their users via a web browser--and which cannot secure a client secret)
               - authorization_code, password (clients with permission to authenticate their users via either a web browser or username/password; limited to first-party apps and potentially certain enterprise customers)
               - password (clients with permission to authenticate their users via username/password only; limited to first-party apps and potentially certain enterprise customers)
               - implicit (public clients only able to authenticate their users via a web browser--and which cannot protect a client secret)
               - authorization_code, implicit (public clients only able to authenticate their users via a web browser--and which cannot secure a client secret)
               - client_credentials (server applications)
             * we also restrict the selection of token_endpoint_auth_method accordingly.
               - authorization_code: token_endpoint_auth_method of none or client_secret_basic (client_secret_post may be added in the future, on a per-software-id basis)
               - authorization_code, password: token_endpoint_auth_method of client_secret_basic (client_secret_post may be added in the future, on a per-software-id basis)
               - password: token_endpoint_auth_method of client_secret_basic (client_secret_post may be added in the future, on a per-software-id basis)
               - implicit: token_endpoint_auth_method of none
               - authorization_code, implicit: token_endpoint_auth_method of none
               - client_credentials: token_endpoint_auth_method of client_secret_basic (client_secret_post may be added in the future, on a per-software-id basis)
             * by default, our implementation disallows a token_endpoint_auth_method of client_secret_post as allowed by the OAuth 2.0 specification (for security considerations)
            */
            // restrict combinations of grant_types as appropriate; NOTE: a client may technically register for multiple client_ids if it needs to support conflicting grant_types
            if (grantTypes.Contains(OAuth2GrantType.AuthorizationCode))
            {
                if (grantTypes.Contains(OAuth2GrantType.Implicit) && tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None)
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_AUTHORIZATION_CODE + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "' for confidential clients.").ConfigureAwait(false);
                    return;
                }
                else if (grantTypes.Contains(OAuth2GrantType.ClientCredentials))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_AUTHORIZATION_CODE + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "'.").ConfigureAwait(false);
                    return;
                }
            }
            else if (grantTypes.Contains(OAuth2GrantType.Password))
            {
                if (grantTypes.Contains(OAuth2GrantType.Implicit))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "'.").ConfigureAwait(false);
                    return;
                }
                else if (grantTypes.Contains(OAuth2GrantType.ClientCredentials))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "'.").ConfigureAwait(false);
                    return;
                }
            }
            else if (grantTypes.Contains(OAuth2GrantType.Implicit))
            {
                if (grantTypes.Contains(OAuth2GrantType.ClientCredentials))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "'.").ConfigureAwait(false);
                    return;
                }
            }
            // restrict the grant_type of RefreshToken to grant_types that support it (and also make sure that token_endpoint_auth_method is not 'none').
            if (grantTypes.Contains(OAuth2GrantType.RefreshToken))
            {
                if (grantTypes.Contains(OAuth2GrantType.Implicit))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_IMPLICIT + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_REFRESH_TOKEN + "'.").ConfigureAwait(false);
                    return;
                }
                else if (grantTypes.Contains(OAuth2GrantType.ClientCredentials))
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_REFRESH_TOKEN + "'.").ConfigureAwait(false);
                    return;
                }
                else if (tokenEndpointAuthMethod == OAuth2TokenEndpointAuthMethod.None)
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "token_endpoint_auth_method '" + OAuth2Convert.TOKEN_ENDPOINT_NONE + "' cannot be combined with grant_type '" + OAuth2Convert.GRANT_TYPE_REFRESH_TOKEN + "'.").ConfigureAwait(false);
                    return;
                }
            }
            // client_secret_post is not supported for security reasons
            if (tokenEndpointAuthMethod == OAuth2TokenEndpointAuthMethod.ClientSecretPost)
            {
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "token_endpoint_auth_method '" + OAuth2Convert.TOKEN_ENDPOINT_CLIENT_SECRET_POST + "'is not allowed.").ConfigureAwait(false);
                return;
            }
            // restrict token_endpoint_auth_method, based on the selection of grant type.
            if (grantTypes.Contains(OAuth2GrantType.AuthorizationCode))
            {
                if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.ClientSecretBasic && tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None)
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_AUTHORIZATION_CODE + "' must use token_endpoint_auth_method '" + OAuth2Convert.TOKEN_ENDPOINT_CLIENT_SECRET_POST + "' or '" + OAuth2Convert.TOKEN_ENDPOINT_NONE + " '.").ConfigureAwait(false);
                    return;
                }
            }
            if (grantTypes.Contains(OAuth2GrantType.Implicit))
            {
                if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None)
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "' must use token_endpoint_auth_method '" + OAuth2Convert.TOKEN_ENDPOINT_NONE + "'.").ConfigureAwait(false);
                    return;
                }
            }
            if (grantTypes.Contains(OAuth2GrantType.Password))
            {
                if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.ClientSecretBasic)
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS + "' must use token_endpoint_auth_method '" + OAuth2Convert.TOKEN_ENDPOINT_CLIENT_SECRET_POST + "'.").ConfigureAwait(false);
                    return;
                }
            }
            if (grantTypes.Contains(OAuth2GrantType.ClientCredentials))
            {
                if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.ClientSecretBasic)
                {
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "' must use token_endpoint_auth_method '" + OAuth2Convert.TOKEN_ENDPOINT_CLIENT_SECRET_POST + "'.").ConfigureAwait(false);
                    return;
                }
            }

            // verify that software_id belongs to the supplied Bearer token (initial access token); if not, fail immediately.
            if (softwareId != oauth2InitialAccessToken.SoftwareId)
            {
                HttpHelper.SetHttpResponseForbidden(context);
                return;
            }

            /* NOTE: with the exception of Strombus-first-party-app-initial-access-tokens, intial access tokens are assigned to (and restricted to) a specific account */
            string initialAccessTokenAccountId = oauth2InitialAccessToken.AccountId;
            // if an initialAccessToken was provided and is restricted to a single accountId, verify that the hostname-supplied accountId matches the initialAccessTokenAccountId
            if ((initialAccessTokenAccountId != null) && (initialAccessTokenAccountId != accountId))
            {
                HttpHelper.SetHttpResponseForbidden(context);
                return;
            }

            /* NOTE: realistically, we probably only want to allow "authentication_code" authorization for first-party clients at first...and then let them "upgrade" their registration to
             *       instead/also support password authentication via app trust/vertification mechanisms (such as push notification channel communciations tied to our app id/certificate). */
            if (grantTypes.Contains(OAuth2GrantType.Password))
            {
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "' is not allowed for this software_id'.").ConfigureAwait(false);
                return;
            }
            if (grantTypes.Contains(OAuth2GrantType.ClientCredentials))
            {
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT_METADATA, "grant_type '" + OAuth2Convert.GRANT_TYPE_CLIENT_CREDENTIALS + "' is not allowed for this software_id'.").ConfigureAwait(false);
                return;
            }

            // generate the actual client registration
            /* if this is an account-specific client, pass in the account ID so that the client is registered to the appropriate account, on the appropriate account login servers, etc. */
            string authServerId = null;
            if (accountId != null)
            {
                authServerId = accountId.ToLowerInvariant() + "-";
            }
            authServerId += serverId;
            OAuth2Client client = OAuth2Client.NewClient(authServerId, accountId);
            // NOTE: client.Id, client.Secret and client.issuedAt will be generated by the SaveTokenAsync method.  
            //       client.AccountId was permanently assigned in the NewClient(accountId) constructor.
            //       client.IsCached will be set appropriately by the SaveTokenAsync method (false if the token originates here or is generated by another server and not cached; 
            //         true if the token is generated by another server and then cached here)
            client.ExpiresAt = null;
            client.SoftwareId = softwareId;
            client.SoftwareVersion = softwareVersion;
            client.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
            client.RedirectUris.AddRange(redirectUris);
            client.GrantTypes.AddRange(grantTypes);
            client.ResponseTypes.AddRange(responseTypes);
            //client.Scopes.AddRange(scopes);
            // save the token; this places it in the database
            await client.SaveClientAsync();

            // return the client registration
            HttpHelper.SetHttpResponseCreated(context, null);
            context.Response.ContentType = "application/json";
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["Pragma"] = "no-store";
            //
            RegisterClientResponse response = new RegisterClientResponse();
            response.client_id = client.Id;
            response.client_secret = client.Secret;
            response.client_id_issued_at = client.IssuedAt?.ToUnixTimeSeconds();
            if (client.Secret != null)
            {
                response.client_secret_expires_at = client.ExpiresAt?.ToUnixTimeSeconds() ?? 0;
            }
            response.software_id = client.SoftwareId;
            response.software_version = client.SoftwareVersion;
            response.redirect_uris = client.RedirectUris.ToArray();
            response.token_endpoint_auth_method = OAuth2Convert.ConvertTokenEndpointAuthMethodToString(client.TokenEndpointAuthMethod);
            List<string> registeredGrantTypesAsStrings = new List<string>();
            foreach (OAuth2GrantType grantType in client.GrantTypes)
            {
                registeredGrantTypesAsStrings.Add(OAuth2Convert.ConvertGrantTypeToString(grantType));
            }
            response.grant_types = registeredGrantTypesAsStrings.ToArray();
            List<string> registeredResponseTypesAsStrings = new List<string>();
            foreach (OAuth2ResponseType responseType in client.ResponseTypes)
            {
                registeredResponseTypesAsStrings.Add(OAuth2Convert.ConvertResponseTypeToString(responseType));
            }
            response.response_types = registeredResponseTypesAsStrings.ToArray();
            response.scope = string.Join(" ", client.Scopes.ToArray());
            //
            response.registration_client_uri = "https://" + (accountId != null ? accountId + "-" : "") + "login.example.com/oauth2/register/" + response.client_id;
            response.registration_access_token = client.RegistrationToken;
            //
            string jsonEncodedResponse = JsonConvert.SerializeObject(response, Formatting.None, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore });
            await context.Response.WriteAsync(jsonEncodedResponse).ConfigureAwait(false);
        }

        #endregion REGISTRATION API

        #region AUTHENTICATION API 

        private async Task AuthorizeClientAsync(HttpContext context)
        {
            /* NOTES:
             * This function authenticates the user and the client and issues an OAuth2 code or token based on one of the following grant types:
             * - Authorization Code (requires follow-up client call to TOKEN endpoint)
             * - Implicit (token issued directly from the authorization endpoint)
             * 
             * NOTE: this function is an OAuth2 Authorization endpoint, compliant with the OAuth2 protocol (RFC6749).
             */

            // NOTE: for security purposes, we validate the client_id and redirect_uri first (since errors are sent to the redirect_uri if it's valid...we need to validate the redirect_uri first)
            string clientId = context.Request.Query["client_id"];
            // treat empty client ids the same as missing client ids.
            if (clientId != null && clientId.Trim() == string.Empty)
            {
                clientId = null;
            }
            // if the client id is missing, send a human-readable message and abort.
            if (clientId == null)
            {
                return;
            }
            // verify that our server handles the clientId's accountId (or that we handle being a root server, if the clientId is from a root server)
            var clientIdParts = ParsingHelper.ExtractServerDetailsFromAccountServerIdIdentifier(clientId);
            if (clientIdParts == null)
            {
                return;
            }
            // NOTE: we currently handle login for ANY client_id issued by the root server or our client
            if (clientIdParts?.AccountId != null)
            {
                var verifiedClientIdParts = await RedisHelper.VerifyAccountIdAndServerIdAsync(_redisClient, LOGIN_SERVICE_NAME, clientIdParts?.AccountId, false, null);
                if (verifiedClientIdParts.Success == false)
                {
                    // NOTE: this error, really, is indicating that they're trying to use our server to service an account from ANOTHER account's server
                    return;
                }
            }
            //
            string redirectUri = context.Request.Query["redirect_uri"];
            // treat an empty redirect_uri the same as a missing redirect_uri.
            if (redirectUri != null && redirectUri.Trim() == string.Empty)
            {
                redirectUri = null;
            }
            // store an extra copy of the originally-provided redirectUri; we'll use this as a state value in CODE requests to match up the redirect_uri in the TOKEN phase.
            string redirectUriForState = redirectUri;

            // load the client; we'll use this to validate the redirect_uri and also use it further in this function; 
            OAuth2Client client = await OAuth2Client.LoadClientAsync(clientId);

            // if the client could not be loaded (i.e. is invalid), send a human-readable message and abort.
            if (client == null)
            {
                return;
            }

            // if the client has only one redirect_uri permitted (which is an absolute uri), and if the caller omitted the redirect_uri here, then we can assume the single valid uri.
            if (client.RedirectUris != null && client.RedirectUris.Count == 1 && redirectUri == null)
            {
                /* NOTE: if we ever support wildcard-type redirect_uris (carefully, as specifically supported by the oauth2 spec), we'll need to verify "absolute uri" status here. */
                redirectUri = client.RedirectUris[0];
            }

            // if the redirect uri is missing and the client did not have a single redirect_uri assigned to it, send a human-readable message and abort.
            if (redirectUri == null)
            {
                return;
            }
            // if the redirect uri does not match the permitted redirect uris, send a human-readable message and abort.
            if (client.RedirectUris.Contains(redirectUri, new OAuth2RedirectUriComparer()) == false)
            {
                return;
            }

            string responseTypeAsString = context.Request.Query["response_type"];
            // treat an empty response_type the same as a missing response_type.
            if (responseTypeAsString != null && responseTypeAsString.Trim() == string.Empty)
            {
                responseTypeAsString = null;
            }
            //
            if (responseTypeAsString == null)
            {
                // if an invalid value was supplied, return immediately with an error.
                SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri(context, null, redirectUri, ERROR_INVALID_REQUEST, "The response_type is missing.");
                return;
            }
            OAuth2ResponseType? responseType = OAuth2Convert.ConvertStringToResponseType(responseTypeAsString);
            if (responseType == null)
            {
                // if an invalid value was supplied, return immediately with an error.
                SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri(context, responseType, redirectUri, ERROR_INVALID_REQUEST, "The response_type is malformed or unsupported.");
                return;
            }
            // verify that the response_type is valid for this endpoint
            switch (responseType)
            {
                case OAuth2ResponseType.Code:
                case OAuth2ResponseType.Token:
                    break;
                default:
                    // if an invalid response_type was supplied, return immediately with an error.
                    SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri(context, responseType, redirectUri, ERROR_UNSUPPORTED_RESPONSE_TYPE, "The response_type is not supported.");
                    return;
            }
            // verify that the response_type is supported for this client
            if (client.ResponseTypes == null || client.ResponseTypes.Contains(responseType.Value) == false)
            {
                // if an invalid response_type was supplied, return immediately with an error.
                SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri(context, responseType, redirectUri, ERROR_UNAUTHORIZED_CLIENT, "The response_type is not authorized for this client.");
                return;
            }

            string scope = context.Request.Query["scope"];
            if (scope != null && scope.Trim() == string.Empty)
            // treat an empty scope value the same as a missing scope value.
            {
                scope = null;
            }
            // NOTE: this implementation does not implement (and therefore rejects) OAuth2 'scope'
            if (scope != null)
            {
                SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri(context, responseType, redirectUri, ERROR_INVALID_SCOPE, "The scope is not authorized.");
                return;
            }

            string state = context.Request.Query["state"];
            if (state != null && state.Trim() == string.Empty)
            // treat an empty state value the same as a missing state value.
            {
                state = null;
            }

            // now that we have validated the parameters, base our remaining logic on the HTTP method used for this page
            switch (context.Request.Method.ToUpperInvariant())
            {
                case "GET": // request for login page
                    {
                        // check the user-agent
                        string userAgentString = context.Request.Headers["User-Agent"];
                        var browserDetails = BrowserDetectionHelper.ConvertUserAgentStringToBrowserDetails(userAgentString);
                        bool browserSupportsFoundation6 = BrowserDetectionHelper.BrowserSupportsFoundation6(browserDetails);

                        // load the appropriate HTML content into memory
                        var assemblyName = new AssemblyName("Strombus.OAuth2Service");
                        var assembly = Assembly.Load(assemblyName);
                        Stream htmlStream;
                        if (browserSupportsFoundation6)
                        {
                            htmlStream = assembly.GetManifestResourceStream("Strombus.OAuth2Service.LoginHtml.default_richui.htm");
                        }
                        else
                        {
                            htmlStream = assembly.GetManifestResourceStream("Strombus.OAuth2Service.LoginHtml.default_basicui.htm");
                        }
                        string htmlSource;
                        using (var reader = new StreamReader(htmlStream, Encoding.UTF8))
                        {
                            htmlSource = reader.ReadToEnd();
                        }

                        // return the generated to the user
                        HttpHelper.SetHttpResponseOk(context);
                        context.Response.ContentType = "text/html";
                        context.Response.Headers["Cache-Control"] = "no-store";
                        context.Response.Headers["Pragma"] = "no-store";
                        await context.Response.WriteAsync(htmlSource);
                    }
                    break;
                case "POST": // submission of username/password
                    {
                        string username = context.Request.Form["username"];
                        if (username != null && username.Trim() == string.Empty)
                        // treat an empty username value the same as if it were missing.
                        {
                            username = null;
                        }
                        if (username == null)
                        {
                            return;
                        }
                        string password = context.Request.Form["password"];
                        if (password != null && password.Trim() == string.Empty)
                        // treat an empty password value the same as if it were missing.
                        {
                            password = null;
                        }
                        if (password == null)
                        {
                            return;
                        }

                        // convert our username to lowercase and remove leading/trailing spaces
                        username = username.Trim().ToLowerInvariant();
                        // remove leading/trailing spaces from our password
                        password = password.Trim();

                        /* if login is occuring via an account-specific login server, capture that account restriction now 
                         * (only users belonging to this account may log in). */
                        var serverDetails = ParsingHelper.ExtractServerDetailsFromHostname(context.Request.Headers["Host"]);
                        string restrictToAccountId = serverDetails?.AccountId;
                        // if the requested server is not a "login" server, return an error.
                        if (serverDetails?.ServerType != LOGIN_SERVICE_NAME)
                        {
                            HttpHelper.SetHttpResponseInternalServerError(context);
                            return;
                        }

                        /* extract the accountId and userId from the username
                         * - if an e-mail address was provided, look up the accountId and userId.
                         * - if no account was provided, assume our server's hostname's account if this is not a root login server */
                        var parsedUsername = await ExtractAccountIdAndUserIdFromUsernameAsync(restrictToAccountId, username);
                        string accountId = parsedUsername.AccountId;
                        string userId = parsedUsername.UserId;
                        
                        if (accountId == null)
                        {
                            return;
                        }
                        if (userId == null)
                        {
                            return;
                        }
                        if (accountId != null && restrictToAccountId != null && accountId != restrictToAccountId)
                        {
                            return;
                        }

                        // if the client is tied to one specific account--but the login credentials are from another account--then abort and return an error.
                        if (client.AccountId != null && client.AccountId != accountId)
                        {
                            return;
                        }

                        /* verify that the user's account exists and that the password is correct. */
                        bool signinSuccess = await CheckUserPasswordAsync(accountId, userId, password);
                        if (signinSuccess == false)
                        {
                            return;
                        }

                        // authentication successful: return the requested authorization code or access token.
                        string location = null;
                        switch (responseType)
                        {
                            case OAuth2ResponseType.Code:
                                {
                                    // generate an authorization code
                                    OAuth2AuthorizationCode authCode = OAuth2AuthorizationCode.NewAuthCode(accountId + "-1");
                                    authCode.ClientId = clientId;
                                    authCode.AccountId = accountId;
                                    authCode.UserId = userId;
                                    authCode.RedirectUri = redirectUriForState;
                                    authCode.ExpirationTime = DateTimeOffset.UtcNow.AddSeconds(AUTHORIZATION_CODE_TIMEOUT_SECONDS);
                                    // save our new auth code to the registry 
                                    // NOTE: unlike tokens, we only save the auth code on this server; we do not propogate short-term auth codes between servers.
                                    await authCode.SaveAuthCodeAsync();

                                    // add the authorization code and (optional) state to the redirect uri 
                                    UriBuilder locationUriBuilder = new UriBuilder(redirectUri);
                                    string query = "code=" + WebUtility.UrlEncode(authCode.Id);
                                    if (state != null)
                                    {
                                        query += "&state=" + WebUtility.UrlEncode(state);
                                    }
                                    locationUriBuilder.Query += (locationUriBuilder.Query.Length > 0 ? "&" : "") + query;
                                    location = locationUriBuilder.ToString();
                                }
                                break;
                            case OAuth2ResponseType.Token:
                                {
                                    // generate a session token
                                    OAuth2Token token = await CreateNewTokenAsync(accountId + "-1", clientId, accountId, userId);

                                    // add the token and (optional) state to the redirect uri 
                                    UriBuilder locationUriBuilder = new UriBuilder(redirectUri);
                                    string fragment = "access_token=" + WebUtility.UrlEncode(token.Id);
                                    fragment += "&token_type=bearer";
                                    if (token.ExpirationTime != null)
                                    {
                                        fragment += "&expires_in=" + WebUtility.UrlEncode(((long)token.ExpirationTime?.Subtract(DateTimeOffset.UtcNow).TotalSeconds).ToString());
                                    }
                                    // NOTE: the current implementation does not support OAuth2 'scope' 
                                    //fragment += "&scope=" + WebUtility.UrlEncode(token.Scope);
                                    if (state != null)
                                    {
                                        fragment += "&state=" + WebUtility.UrlEncode(state);
                                    }
                                    locationUriBuilder.Fragment = fragment;
                                    location = locationUriBuilder.ToString();
                                }
                                break;
                        }

                        // return the new code/token
                        HttpHelper.SetHttpResponseFound(context, location);
                }
                break;
            }
        }

        private async Task<OAuth2Token> CreateNewTokenAsync(string authServerId, string clientId, string accountId, string userId)
        {
            OAuth2Token token = OAuth2Token.NewToken(authServerId);
            token.ClientId = clientId;
            token.AccountId = accountId;
            token.UserId = userId;
            // save our token to the token registry
            await token.SaveTokenAsync();

            return token;
        }

        private struct ExtractAccountIdAndUserIdFromUsernameResult
        {
            public string AccountId;
            public string UserId;
        }
        private async Task<ExtractAccountIdAndUserIdFromUsernameResult> ExtractAccountIdAndUserIdFromUsernameAsync(string defaultAccountId, string username)
        {
            ExtractAccountIdAndUserIdFromUsernameResult result = new ExtractAccountIdAndUserIdFromUsernameResult();

            if (username.Contains('@'))
            {
                // if the supplied username is an e-mail address, look up the actual accountId and userId now.
                var lookupUserResult = await User.LookupUserByEmailAddressAsync(username);
                if (lookupUserResult == null)
                {
                    result.AccountId = null;
                    result.UserId = null;
                }
                else 
                {
                    result.AccountId = lookupUserResult?.AccountId;
                    result.UserId = lookupUserResult?.UserId;
                }
            }
            else if (username.Contains('/'))
            {
                // if the supplied username contains a forward-slash, parse the account-id and user-id
                result.AccountId = username.Substring(0, username.IndexOf('/'));
                string accountSpecificUsername = username.Substring(username.IndexOf('/') + 1);
                result.UserId = await User.ConvertUsernameToUserIdAsync(result.AccountId, accountSpecificUsername);
            }
            else if (username.Contains('\\'))
            {
                // if the supplied username contains a back-slash, parse the account-id and user-id
                result.AccountId = username.Substring(0, username.IndexOf('\\'));
                string accountSpecificUsername = username.Substring(username.IndexOf('\\') + 1);
                result.UserId = await User.ConvertUsernameToUserIdAsync(result.AccountId, accountSpecificUsername);
            }
            else
            {
                // otherwise, treat the username as a local username
                if (defaultAccountId != null)
                {
                    result.AccountId = defaultAccountId;
                }
                string accountSpecificUsername = username;
                result.UserId = await User.ConvertUsernameToUserIdAsync(result.AccountId, accountSpecificUsername);
            }

            return result;
        }

        private async Task<bool> CheckUserPasswordAsync(string accountId, string userId, string password)
        {
            // load the user
            User user = await User.LoadUserAsync(accountId, userId);
            // if the user could not be found, return false.
            if (user == null)
            {
                return false;
            }

            // verify that the password matches
            bool passwordMatches = await user.VerifyPasswordAsync(password);
            return passwordMatches;
        }

        // this function is used to return errors using an OAuth2 JSON error response
        async Task SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(HttpContext context, string error, string errorDescription)
        {
            HttpHelper.SetHttpResponseUnauthorized(context);
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["Pragma"] = "no-store";
            context.Response.ContentType = "application/json";
            OAuth2ErrorResponse errorResponse = new OAuth2ErrorResponse() { error = error, error_description = errorDescription };
            await context.Response.WriteAsync(JsonConvert.SerializeObject(errorResponse)).ConfigureAwait(false);
        }

        private void SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri(HttpContext context, OAuth2ResponseType? responseType, string baseUri, string error, string errorDescription)
        {
            switch (responseType)
            {
                case OAuth2ResponseType.Code:
                case null:
                    SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri_Query(context, baseUri, error, errorDescription);
                    break;
                case OAuth2ResponseType.Token:
                    SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri_Fragment(context, baseUri, error, errorDescription);
                    break;
            }
        }

        // this function is used to return errors from the authorization endpoint using redirection (For authorization code flow)
        private void SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri_Query(HttpContext context, string baseUri, string error, string errorDescription)
        {
            UriBuilder locationUriBuilder = new UriBuilder(baseUri);
            string query = "error=" + WebUtility.UrlEncode(error);
            if (errorDescription != null)
            {
                query += "&error_description=" + WebUtility.UrlEncode(errorDescription);
            }
            locationUriBuilder.Query += (locationUriBuilder.Query.Length > 0 ? "&" : "") + query;

            HttpHelper.SetHttpResponseFound(context, locationUriBuilder.ToString());
        }

        // this function is used to return errors from the authorization endpoint using redirection (for implicit flow)
        private void SetHttpResponseFound_OAuth2ErrorResponseUsingRedirectUri_Fragment(HttpContext context, string baseUri, string error, string errorDescription)
        {
            UriBuilder locationUriBuilder = new UriBuilder(baseUri);
            string fragment = "error=" + WebUtility.UrlEncode(error);
            if (errorDescription != null)
            {
                fragment += "&error_description=" + WebUtility.UrlEncode(errorDescription);
            }
            locationUriBuilder.Fragment = fragment;

            HttpHelper.SetHttpResponseFound(context, locationUriBuilder.ToString());
        }

        #endregion AUTHENTICATION API

        #region REDIRECT ENDPOINT

        private async Task ProcessRedirectEndpointAsync(HttpContext context)
        {
            HttpHelper.SetHttpResponseOk(context);
            await context.Response.WriteAsync("<html><head></head><body></body></html>");

            //HttpHelper.SetHttpResponseNoContent(context);
        }

        #endregion REDIRECT ENDPOINT

        #region TOKEN API

        private struct IssueTokenResponse
        {
            public string access_token;
            public string token_type;
            public long? expires_in;
            public string refresh_token;
            public string scope;
        }
        private async Task IssueTokenAsync(HttpContext context)
        {
            /* NOTES:
             * This function authenticates the client and issues an OAuth2 token based on one of the following grant types:
             * - Authorization Code (requires previous client call to CODE endpoint)
             * - Password
             * - Client Credentials Grant
             * 
             * NOTE: this function is an OAuth2 Token endpoint, compliant with the OAuth2 protocol (RFC6749).
             */

            if (await HttpHelper.VerifyContentTypeHeaderIsWwwFormUrlEncodedAsync(context).ConfigureAwait(false) == false)
                return;

            string grantTypeAsString = context.Request.Form["grant_type"];
            if (grantTypeAsString == null)
            {
                // if an invalid value was supplied, return immediately with an error.
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_REQUEST, "The grant_type is missing.").ConfigureAwait(false);
                return;
            }
            OAuth2GrantType? grantType = OAuth2Convert.ConvertStringToGrantType(grantTypeAsString);
            if (grantType == null)
            {
                // if an invalid value was supplied, return immediately with an error.
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_UNSUPPORTED_GRANT_TYPE, "The grant_type is malformed or unsupported.").ConfigureAwait(false);
                return;
            }

            /* NOTE: although the client registration process may optionally prohibit OAuth2TokenEndpointAuthMethod.Post, we support it here for completeness.
             *       (and we return immediately with an error if the registered client tried to use OAuth2TokenEndpointAuthMethod.Post without prior permission). */

            OAuth2TokenEndpointAuthMethod tokenEndpointAuthMethod = OAuth2TokenEndpointAuthMethod.None;
            string clientId = null;
            string clientSecret = null;

            // check for an authorization header first...then for POST form encoded client credentials
            string authorizationHeader = context.Request.Headers["Authorization"];
            if (authorizationHeader != null)
            {
                // OAuth2TokenEndpointAuthMethod.ClientSecretBasic
                tokenEndpointAuthMethod = OAuth2TokenEndpointAuthMethod.ClientSecretBasic;

                // verify that BASIC authentication is being used
                string authorizationScheme = authorizationHeader?.Split(' ')[0].ToLowerInvariant();
                if (authorizationScheme != "basic")
                {
                    // if the authentication scheme is missing or unsupported, return immediately with an error.
                    await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "The requested authorization scheme is not supported.").ConfigureAwait(false);
                    return;
                }
                // parse client_id and client_password
                if (authorizationHeader.IndexOf(' ') < 0)
                {
                    // if the client id/password is missing, return immediately with an error.
                    await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "The authorization header is malformed.").ConfigureAwait(false);
                    return;
                }
                // make sure that the POST method wasn't also used (in addition to BASIC authentication).
                if ((string)context.Request.Form["client_id"] != null || (string)context.Request.Form["client_secret"] != null)
                {
                    // if multiple authentication methods are used, return immediately with an error.
                    await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "Multiple authentication methods may not be used in a single request.").ConfigureAwait(false);
                    return;
                }

                string base64EncodedClientIdAndSecret = authorizationHeader.Substring(authorizationHeader.IndexOf(' ') + 1).Trim();
                string clientIdAndSecretConcatenated = Encoding.UTF8.GetString(Convert.FromBase64String(base64EncodedClientIdAndSecret));
                if (clientIdAndSecretConcatenated.IndexOf(':') < 0)
                {
                    // if the client id/password is malformed, return immediately with an error
                    await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "The client_id are/on client_secret are malformed.").ConfigureAwait(false);
                    return;
                }
                clientId = clientIdAndSecretConcatenated.Substring(0, clientIdAndSecretConcatenated.IndexOf(':'));
                clientSecret = clientIdAndSecretConcatenated.Substring(clientIdAndSecretConcatenated.IndexOf(':') + 1);
            }
            else
            {
                clientId = context.Request.Form["client_id"];

                if ((string)context.Request.Form["client_secret"] != null)
                {
                    // OAuth2TokenEndpointAuthMethod.ClientSecretPost
                    tokenEndpointAuthMethod = OAuth2TokenEndpointAuthMethod.ClientSecretPost;

                    clientSecret = context.Request.Form["client_secret"];
                }
                else
                {
                    // OAuth2TokenEndpointAuthMethod.None
                    tokenEndpointAuthMethod = OAuth2TokenEndpointAuthMethod.None;
                }
            }
            // verify that a client_id was provided
            if (clientId == null)
            {
                // if the client_id is missing, return immediately with an error.
                await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "A client_id must be provided.").ConfigureAwait(false);
                return;
            }
            // verify that a client_secret was provided for confidential clients.
            if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None && clientSecret == null)
            {
                // if the client_secret is missing for a confidential client, return immediately with an error.
                await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "A client_secret must be provided.").ConfigureAwait(false);
                return;
            }

            // retrieve the client from our Redis datastore; NOTE: this function will return (null) if the client_id/client_secret could not be found.
            OAuth2Client client = await OAuth2Client.LoadClientAsync(clientId);

            if (client != null)
            {
                // if the client exists but does not match the supplied secret, fail with an appropriate error.
                if (client.VerifySecret(clientSecret) == false)
                {
                    await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "The client_id and/or client_secret are incorrect.").ConfigureAwait(false);
                    return;
                }
            }

            if (client == null)
            {
                /* client does not exist, so fail with an appropriate error. */
                await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "The client_id and/or client_secret are incorrect.").ConfigureAwait(false);
                return;
            }

            // verify that the client supports the authentication method used in this request
            if (client.TokenEndpointAuthMethod != tokenEndpointAuthMethod)
            {
                // if the auth method used is not allowed for this client, return immediately with an error.
                await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "This authentication method is not supported for this client.").ConfigureAwait(false);
                return;
            }
            // verify that the client is not expired
            if (client.ExpiresAt != null && client.ExpiresAt.Value < DateTimeOffset.UtcNow)
            {
                // if the client is expired, return immediately with an error.
                await SetHttpResponseUnauthorizedAsync_OAuth2ErrorResponse(context, ERROR_INVALID_CLIENT, "Client is expired.").ConfigureAwait(false);
                return;
            }
            // verify that the client is authorized to use this grant type
            if (!client.GrantTypes.Contains(grantType.Value))
            {
                // if the client cannot authenticate using this grant type, return immediately with an error.
                await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_UNAUTHORIZED_CLIENT, "The client is not authorized for the requested grant_type.").ConfigureAwait(false);
                return;
            }

            // process the request based on grant type
            OAuth2Token token = null;
            switch (grantType)
            {
                case OAuth2GrantType.AuthorizationCode:
                    {
                         * NOTE: the no-secret authorization_code grant, I believe, may be designed for public clients which have the client_id embedded in them (i.e. don't use
                         *       dynamic client registration) since it's not safe to distribute a client_secret with an application; it's fine, however, to store a client_secret
                         *       per each instance of an app, created during client registration.
                         * NOTE: the no-secret auhorization_code grant might also be valid or even preferable for web browsers that store their client_id, along with storing
                         *       a refresh token.  But that could also be a very bad idea.  Research further. */

                        string authCodeId = context.Request.Form["code"];
                        if (authCodeId == null)
                        {
                            /* auth code not provided */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "An authorization code is required.").ConfigureAwait(false);
                            return;
                        }

                        OAuth2AuthorizationCode authCode = await OAuth2AuthorizationCode.LoadAuthCodeAsync(authCodeId);
                        if (authCode == null)
                        {
                            /* auth code invalid or expired */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "The authorization code is invalid or expired.").ConfigureAwait(false);
                            return;
                        }

                        if (authCode.IsUsed)
                        {
                            /* auth code already used */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "The authorization code has been revoked.").ConfigureAwait(false);
                            return;
                        }

                        string redirectUri = context.Request.Form["redirect_uri"];
                        // treat an empty redirect_uri the same as a missing redirect_uri.
                        if (redirectUri != null && redirectUri.Trim() == string.Empty)
                        {
                            redirectUri = null;
                        }
                        string redirectUriVerify = authCode.RedirectUri;
                        // make sure that the redirect_uri provided to the TOKEN endpoint matches the redirect_uri provided to the CODE endpoint
                        if (new OAuth2RedirectUriComparer().Equals(redirectUri, redirectUriVerify) == false)
                        {
                            /* redirect_uri does not match */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "The redirect_uri does not match the original request.").ConfigureAwait(false);
                            return;
                        }

                        /* make sure that the authenticated clientId matches the code's clientId */
                        if (authCode.ClientId != client.Id)
                        {
                            /* auth code clientId does not match the authenticated clientId; return the appropriate error. */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "This authorization code was issued to another client.").ConfigureAwait(false);
                            return;
                        }

                        /* if login is occuring via an account-specific login server, capture that account restriction now 
                         * (only users belonging to this account may log in). */
                        var restrictToAccountIdServerDetails = ParsingHelper.ExtractServerDetailsFromHostname(context.Request.Headers["Host"]);
                        string restrictToAccountId = restrictToAccountIdServerDetails?.AccountId;

                        if (authCode.AccountId != null && restrictToAccountId != null && authCode.AccountId != restrictToAccountId)
                        {
                            /* return the appropriate error for "only codes generated by this account's login server are valid." */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "This authorization code is not valid for this account.").ConfigureAwait(false);
                            return;
                        }

                        /* CRITICAL: mark this code as used, to prevent cross-domain theft of credentials (i.e. by another browser window requesting an extra token). */
                        await authCode.MarkAsUsedAsync();

                        // code validated: proceed with token generation.
                        token = await CreateNewTokenAsync(authCode.AccountId + "-1", clientId, authCode.AccountId, authCode.UserId);

                        // save the token in the code (for reference, in case the code is compromised before expiration and the token potentially needs to be revoked)
                        authCode.TokenId = token.Id;
                        await authCode.SaveAuthCodeAsync();
                    }
                    break;
                case OAuth2GrantType.Password:
                    {
                        // NOTE: the current implementation does not support OAuth2 'scope'
                        //string scope = context.Request.Form["scope"];

                        string username = context.Request.Form["username"];
                        // NOTE: we always trim and convert usernames to lowercase; unlike passwords, account-ids and usernames/email addresses are ALWAYS case-insensitive.
                        username = username.Trim().ToLowerInvariant();

                        string password = context.Request.Form["password"];
                        // trim leading/trailing spaces from passwords, in case they were accidentally entered.
                        password = password.Trim();

                        /* if login is occuring via an account-specific login server, capture that account restriction now 
                         * (only users belonging to this account may log in). */
                        var restrictToAccountIdServerDetails = ParsingHelper.ExtractServerDetailsFromHostname(context.Request.Headers["Host"]);
                        string restrictToAccountId = restrictToAccountIdServerDetails?.AccountId;

                        /* extract the accountId and userId from the username
                         * - if an e-mail address was provided, look up the accountId and userId.
                         * - if no account was provided, assume our server's hostname's account if this is not a root login server */
                        var parsedUsername = await ExtractAccountIdAndUserIdFromUsernameAsync(restrictToAccountId, username);
                        string accountId = parsedUsername.AccountId;
                        string userId = parsedUsername.UserId;

                        if (accountId == null || userId == null)
                        {
                            /* TODO: return the appropriate error for "missing or invalid username" */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "Username is invalid or missing.").ConfigureAwait(false);
                            return;
                        }
                        if (accountId != null && restrictToAccountId != null && accountId != restrictToAccountId)
                        {
                            /* return the appropriate error for "only users for this login server may log in" */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "This username cannot be authenticated with this server.").ConfigureAwait(false);
                            return;
                        }

                        // if the client is tied to one specific account--but the login credentials are from another account--then abort and return an error.
                        if (client.AccountId != null && client.AccountId != accountId)
                        {
                            /* return the appropriate error for "the client does not permit logins for the specified account (i.e. username)" */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "This client is not authorized for users on the specified account.").ConfigureAwait(false);
                            return;
                        }

                        /* verify that the user's account exists and that the password is correct. */
                        bool signinSuccess = await CheckUserPasswordAsync(accountId, userId, password);
                        if (signinSuccess == false)
                        {
                            /* return the appropriate error for "the username and/or password are invalid." */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "The username and/or password are invalid.").ConfigureAwait(false);
                            return;
                        }

                        // user authenticated: proceed with token generation.
                        token = await CreateNewTokenAsync(accountId + "-1", clientId, accountId, userId);
                        await token.SaveTokenAsync();
                    }
                    break;
                case OAuth2GrantType.ClientCredentials:
                    {
                        // sanity check: verify that this client is associated with a specific account
                        if (client.AccountId == null)
                        {
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "The client must be assigned to an account to use this grant type.").ConfigureAwait(false);
                            return;
                        }

                        // NOTE: the current implementation does not support OAuth2 'scope'
                        //string scope = context.Request.Form["scope"];

                        /* if login is occuring via an account-specific login server, capture that account restriction now 
                         * (only users belonging to this account may log in). */
                        var restrictToAccountIdServerDetails = ParsingHelper.ExtractServerDetailsFromHostname(context.Request.Headers["Host"]);
                        string restrictToAccountId = restrictToAccountIdServerDetails?.AccountId;

                        if (client.AccountId != null && restrictToAccountId != null && client.AccountId != restrictToAccountId)
                        {
                            /* return the appropriate error for "only clients belonging to this login server's account may log in" */
                            await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_INVALID_GRANT, "This client must be authenticated by its own account's servers or by root servers.").ConfigureAwait(false);
                            return;
                        }

                        // client authenticated: proceed with token generation.
                        token = await CreateNewTokenAsync(client.AccountId + "-1", clientId, client.AccountId, null);
                        await token.SaveTokenAsync();
                    }
                    break;
                default:
                    // if an invalid/unsupported grant_type was supplied, return immediately with an error.
                    await SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(context, ERROR_UNSUPPORTED_GRANT_TYPE, "The grant_type is malformed or unsupported.").ConfigureAwait(false);
                    return;
            }

            // if a token was generated, return it to our caller now.
            if (token != null)
            {
                // return the new token
                HttpHelper.SetHttpResponseOk(context);
                context.Response.ContentType = "application/json;charset=UTF-8";
                context.Response.Headers["Cache-Control"] = "no-store";
                context.Response.Headers["Pragma"] = "no-store";
                //
                IssueTokenResponse response = new IssueTokenResponse();
                response.access_token = token.Id;
                response.token_type = "bearer";
                if (token.ExpirationTime != null)
                {
                    response.expires_in = (long)token.ExpirationTime.Value.Subtract(DateTimeOffset.UtcNow).TotalSeconds;
                }
                else
                {
                    response.expires_in = null;
                }
                response.refresh_token = token.RefreshTokenId;
                response.scope = string.Join(" ", token.Scopes.ToArray());
                //
                string jsonEncodedResponse = JsonConvert.SerializeObject(response, Formatting.None, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore });
                await context.Response.WriteAsync(jsonEncodedResponse).ConfigureAwait(false);
            }
            else
            {
                /* NOTE: code should always return naturally before this. */
                throw new Exception();
            }
        }

        private struct GetTokenResponse
        {
            public string id;
            public DateTimeOffset? expiration_time;
            public string refresh_token;
            public List<string> scopes;
            public string client_id;
            public string account_id;
            public string user_id;
        }
        private async Task GetTokenAsync(HttpContext context, string tokenId)
        {
            // verify that the authorization header contains a valid OAuth2 token
            if (await HttpHelper.VerifyAcceptHeaderIsJson(context).ConfigureAwait(false) == false)
                return;

            // retrieve our bearer token (i.e. initial access token)
            var authTokenId = HttpHelper.ExtractBearerTokenFromAuthorizationHeaderValue(context.Request.Headers["Authorization"]);
            if (authTokenId != null && authTokenId.Trim() == string.Empty)
            {
                authTokenId = null;
            }
            if (authTokenId == null)
            {
                // if no token was provided, fail immediately and let the client know that they MUST supply a token.
                HttpHelper.SetHttpResponseUnauthorized(context);
                return;
            }
            // attempt to retrieve the token (locally-only, since all trusted servers for this protected resource will be cached locally)
            var authToken = await OAuth2Token.LoadTokenAsync(authTokenId, localOnly: true);
            // if authToken is null then we should fail immediately.
            if (authToken == null)
            {
                HttpHelper.SetHttpResponseUnauthorized(context);
                return;
            }

            // verify that the authToken supports "token-read" scope
            if (!authToken.Scopes.Contains("token-read"))
            {
                HttpHelper.SetHttpResponseForbidden(context);
                return;
            }

            /* NOTE: this is a protected resource; first, retrieve the ssl client's certificate */
            string header_ssl_client_s_dn = context.Request.Headers["X-SSL-Client-S-DN"];
            if (header_ssl_client_s_dn == null || header_ssl_client_s_dn == string.Empty)
            {
                // if there is no client certificate, abort immediately.
                HttpHelper.SetHttpResponseUnauthorized(context);
                return;
            }

            // load the requested token (local only)
            OAuth2Token requestedToken = await OAuth2Token.LoadTokenAsync(tokenId, localOnly: true);
            if (requestedToken == null)
            {
                // if the token does not exist on this server, abort immediately.
                HttpHelper.SetHttpResponseNotFound(context);
                return;
            }

            // make sure that the authToken's and requestedToken's accountIds match
            if (authToken.AccountId != requestedToken.AccountId)
            {
                HttpHelper.SetHttpResponseForbidden(context);
                return;
            }

            // verify that the client certificate matches the authToken's account_id
            string clientSslDn = await GetOAuth2TokenClientSslDn(authToken.AccountId, authTokenId);
            if (clientSslDn != header_ssl_client_s_dn)
            {
                HttpHelper.SetHttpResponseUnauthorized(context);
                return;
            }

            // populate the result
            GetTokenResponse resultToken = new GetTokenResponse()
            {
                id = requestedToken.Id,
                expiration_time = requestedToken.ExpirationTime,
                refresh_token = requestedToken.RefreshTokenId,
                scopes = requestedToken.Scopes,
                client_id = requestedToken.ClientId,
                account_id = requestedToken.AccountId,
                user_id = requestedToken.UserId
            };

            // return the result
            HttpHelper.SetHttpResponseOk(context);
            context.Response.ContentType = "application/json";
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["Pragma"] = "no-store";
            //
            string jsonEncodedResponse = JsonConvert.SerializeObject(resultToken, Formatting.None, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore });
            await context.Response.WriteAsync(jsonEncodedResponse).ConfigureAwait(false);
        }

        async Task<string> GetOAuth2TokenClientSslDn(string accountId, string tokenId)
        {
            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            string fullyQualifiedTokenKey = REDIS_PREFIX_HIGHTRUST_SERVICE_CLIENTS + REDIS_PREFIX_SEPARATOR + accountId + REDIS_SLASH + LOGIN_SERVICE_NAME;
            return await _redisClient.HashGetAsync<string, string, string>(fullyQualifiedTokenKey, tokenId);
        }

        #endregion TOKEN API

        #region OAuth2 Error Responses 

        private class OAuth2ErrorResponse
        {
            public string error;
            public string error_description;
            // NOTE: error_uri is only supported by code/token endpoints
            public string error_uri;
        }

        // this function is used to return errors using an OAuth2 JSON error response
        async Task SetHttpResponseBadRequestAsync_OAuth2ErrorResponse(HttpContext context, string error, string errorDescription)
        {
            HttpHelper.SetHttpResponseBadRequest(context);
            context.Response.ContentType = "application/json";
            OAuth2ErrorResponse errorResponse = new OAuth2ErrorResponse() { error = error, error_description = errorDescription };
            await context.Response.WriteAsync(JsonConvert.SerializeObject(errorResponse)).ConfigureAwait(false);
        }

        #endregion OAuth2 Error Responses 

    }

    public static class BuilderExtensions
    {
        public static IApplicationBuilder UseOAuth2Service(this IApplicationBuilder app)
        {
            return app.UseMiddleware<OAuth2ServiceMiddleware>();
        }
    }
}
