using Strombus.Redis;
using Strombus.ServerShared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public class OAuth2Client
    {
        // Definitions:
        // ORIGIN SERVER: the server which owns and mantains the client registration
        // AUTHORITATIVE SERVER: servers in the same cluster as the origin server--which are the origin server or secondary trusted copies of the client registration
        // CACHED CLIENT: a local copy of the client registration (where the local server subscribes to client registration update/revoke notifications)

        static RedisClient _redisClient = null;

        private const string REDIS_PREFIX_ACCOUNT = "account";
        private const string REDIS_PREFIX_CLIENT = "oauth2client";
        private const string REDIS_PREFIX_LOGIN_SERVICE = "login-service";
        private const string REDIS_PREFIX_SEPARATOR = ":";
        //
        private const string REDIS_ASTERISK = "*";
        private const string REDIS_SLASH = "/";
        //
        private const string REDIS_SUFFIX_GRANT_TYPES = "grant-types";
        private const string REDIS_SUFFIX_OAUTH2CLIENTS = "oauth2clients";
        private const string REDIS_SUFFIX_REDIRECT_URIS = "redirect-uris";
        private const string REDIS_SUFFIX_RESPONSE_TYPES = "response-types";
        private const string REDIS_SUFFIX_SCOPES = "scopes";
        private const string REDIS_SUFFIX_SEPARATOR = "#";

        private ParsingHelper.ServerDetails _loginServerDetails; // the server details of the OAuth2 service (e.g. accountId, serverType, serverId)

        private string _id;
        private string _accountId;
        private bool _accountId_IsDirty = false;
        private string _secret;
        private bool _secret_IsDirty = false;
        private bool _secretIsHashed;
        private DateTimeOffset? _issuedAt;
        private DateTimeOffset? _expiresAt;
        private bool _expiresAt_IsDirty = false;
        private string _softwareId;
        private bool _softwareId_IsDirty = false;
        private string _softwareVersion;
        private bool _softwareVersion_IsDirty = false;
        private OAuth2TokenEndpointAuthMethod _tokenEndpointAuthMethod;
        private bool _tokenEndpointAuthMethod_IsDirty = false;
        private ListWithDirtyFlag<string> _redirectUris;
        private ListWithDirtyFlag<OAuth2GrantType> _grantTypes;
        private ListWithDirtyFlag<OAuth2ResponseType> _responseTypes;
        private ListWithDirtyFlag<string> _scopes;
        /* NOTE: registration tokens require the same level of security as client secrets since a compromised registration token would enable a caller to modify client configuration
         *       surreptitiously (such as changing the push notification config) or could otherwise meddle with clients.  As we allow client_credentials grant flow and as it would be
         *       very hard to get all account holders to revoke and reissue all their web-console-generated client_ids (but not as hard to ask them to reissue the programatic client 
         *       tokens), we store the client's registration token with the same hash-based system as client secrets.  In the unlikely emergency scenario that the Redis datastore is
         *       compromised, the hashes still have sufficiently high tolerance against hacking that the security risk to clients who choose not to re-issue client_ids will be
         *       minimal (or at least minimized).  Also due to this security requirement, we cannot store the registrationToken's id in the "oauth2token:*" Redis keys in cleartext,
         *       so we instead handle it as a special case password of sorts when the /register/{client_id}... uris are being requested. */
        private string _registrationToken;
        private bool _registrationToken_IsDirty = false;
        private bool _registrationTokenIsHashed;
        private Int64? _timeCreatedInUnixMicroseconds; // null for new objects; otherwise the creation timestamp when the object was saved by redis
        private Int64? _timeUpdatedInUnixMicroseconds; // null for new objects; otherwise the last timestamp that the object was saved by redis
        private bool _isCached;

        public enum LoadClientOptions
        {
            LocalClients = 0x01,
            //ClusterClients = 0x02,
            //PeerClients = 0x04,    
            //ChildClients = 0x08
        }

        public static async Task<OAuth2Client> LoadClientAsync(string clientId)
        {
            // default operation: attempt to retrieve the token from our peers or children if necessary--but do not cache the token (since caching requires invalidation notification subscriptions)
            return await LoadClientAsync(clientId, LoadClientOptions.LocalClients /* | LoadClientOptions.PeerClients | LoadClientOptions.ChildClients*/).ConfigureAwait(false);
        }

        public static async Task<OAuth2Client> LoadClientAsync(string clientId, LoadClientOptions options)
        {
            if ((options & LoadClientOptions.LocalClients) == LoadClientOptions.LocalClients)
            {
                if (_redisClient == null)
                {
                    _redisClient = await Singletons.GetRedisClientAsync();
                }

                string fullyQualifiedClientKey = REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + clientId;
                bool localClientExists = (await _redisClient.ExistsAsync(new string[] { fullyQualifiedClientKey }) > 0);
                if (localClientExists)
                {
                    Dictionary<string, string> clientDictionary = await _redisClient.HashGetAllASync<string, string, string>(fullyQualifiedClientKey);

                    string clientIsCachedAsString = clientDictionary.ContainsKey("cached") ? clientDictionary["cached"] : null;
                    bool clientIsCached = (clientIsCachedAsString != null && clientIsCachedAsString != "0");

                    string timeCreatedAsString = clientDictionary.ContainsKey("time-created") ? clientDictionary["time-created"] : null;
                    Int64? timeCreatedInUnixMicroseconds = null;
                    Int64 timeCreatedAsInt64;
                    if (timeCreatedAsString != null && Int64.TryParse(timeCreatedAsString, out timeCreatedAsInt64))
                    {
                        timeCreatedInUnixMicroseconds = timeCreatedAsInt64;
                    }

                    string timeUpdatedAsString = clientDictionary.ContainsKey("time-updated") ? clientDictionary["time-updated"] : null;
                    Int64? timeUpdatedInUnixMicroseconds = null;
                    Int64 timeUpdatedAsInt64;
                    if (timeUpdatedAsString != null && Int64.TryParse(timeUpdatedAsString, out timeUpdatedAsInt64))
                    {
                        timeUpdatedInUnixMicroseconds = timeUpdatedAsInt64;
                    }

                    OAuth2Client resultClient = new OAuth2Client();
                    resultClient._id = clientId;
                    ParsingHelper.ServerDetails? loginServerDetails = ParsingHelper.ExtractServerDetailsFromAccountServerIdIdentifier(clientId);
                    if (loginServerDetails == null)
                    {
                        throw new Exception();
                    }
                    resultClient._loginServerDetails = loginServerDetails.Value;
                    //
                    resultClient._accountId = clientDictionary.ContainsKey("account-id") ? clientDictionary["account-id"] : null;
                    //
                    if (clientDictionary.ContainsKey("issued-at"))
                    {
                        long issuedAtAsLong;
                        if (long.TryParse(clientDictionary["issued-at"], out issuedAtAsLong))
                        {
                            resultClient._issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtAsLong);
                        }
                    }
                    //
                    if (clientDictionary.ContainsKey("secret-hash"))
                    {
                        // load the base64-encoded binary hash of the client secret
                        resultClient._secret = clientDictionary["secret-hash"];
                        resultClient._secretIsHashed = true;
                    }
                    else
                    {
                        resultClient._secret = null;
                        resultClient._secretIsHashed = false;
                    }
                    //
                    if (resultClient._secret != null)
                    {
                        if (clientDictionary.ContainsKey("expires-at"))
                        {
                            long expiresAtAsLong;
                            if (long.TryParse(clientDictionary["expires-at"], out expiresAtAsLong))
                            {
                                resultClient._expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresAtAsLong);
                            }
                        }
                    }
                    //
                    resultClient._softwareId = clientDictionary.ContainsKey("software-id") ? clientDictionary["software-id"] : null;
                    //
                    resultClient._softwareVersion = clientDictionary.ContainsKey("software-version") ? clientDictionary["software-version"] : null;
                    //
                    if (!clientDictionary.ContainsKey("token-endpoint-auth-method"))
                    {
                        // this field is required; return null if it is not present.
                        return null;
                    }
                    resultClient._tokenEndpointAuthMethod = OAuth2Convert.ConvertStringToTokenEndpointAuthMethod(clientDictionary["token-endpoint-auth-method"]).Value;
                    //
                    resultClient._redirectUris = await _redisClient.SetMembersAsync<string, string>(fullyQualifiedClientKey + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_REDIRECT_URIS).ConfigureAwait(false);
                    //
                    List<string> grantTypesAsStrings = await _redisClient.SetMembersAsync<string, string>(fullyQualifiedClientKey + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_GRANT_TYPES).ConfigureAwait(false);
                    if (grantTypesAsStrings != null)
                    {
                        resultClient._grantTypes = new ListWithDirtyFlag<OAuth2GrantType>();
                        foreach (string grantTypeAsString in grantTypesAsStrings)
                        {
                            resultClient._grantTypes.Add(OAuth2Convert.ConvertStringToGrantType(grantTypeAsString).Value);
                        }
                    }
                    //
                    List<string> responseTypesAsStrings = await _redisClient.SetMembersAsync<string, string>(fullyQualifiedClientKey + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_RESPONSE_TYPES).ConfigureAwait(false);
                    if (responseTypesAsStrings != null)
                    {
                        resultClient._responseTypes = new ListWithDirtyFlag<OAuth2ResponseType>();
                        foreach (string responseTypeAsString in responseTypesAsStrings)
                        {
                            resultClient._responseTypes.Add(OAuth2Convert.ConvertStringToResponseType(responseTypeAsString).Value);
                        }
                    }
                    resultClient._scopes = await _redisClient.SetMembersAsync<string, string>(fullyQualifiedClientKey + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_SCOPES).ConfigureAwait(false);
                    //
                    if (clientDictionary.ContainsKey("registration-token-hash"))
                    {
                        // load the base64-encoded binary hash of the client registration token
                        resultClient._registrationToken = clientDictionary["registration-token-hash"];
                        resultClient._registrationTokenIsHashed = true;
                    }
                    else
                    {
                        resultClient._registrationToken = null;
                        resultClient._registrationTokenIsHashed = false;
                    }
                    resultClient._isCached = clientIsCached;
                    resultClient._timeCreatedInUnixMicroseconds = timeCreatedInUnixMicroseconds;
                    resultClient._timeUpdatedInUnixMicroseconds = timeUpdatedInUnixMicroseconds;

                    return resultClient;
                }
            }

            // client could not be found
            return null;
        }

        public bool VerifySecret(string secretToVerify)
        {
            if (secretToVerify == null && _secret != null) return false;
            if (secretToVerify != null && _secret == null) return false;

            // if there is no secret and none was supplied, return true.
            if (secretToVerify == null && _secret == null) return true;

            if (_secretIsHashed == false)
            {
                // secret is in clear-text, so just compare the two values
                return (_secret == secretToVerify);
            }
            else
            {
                // secret is hashed, so calculate the hash of the supplied secretToVerify and then compare the two values.
                return (HashesAreEqual(Convert.FromBase64String(_secret), HashClientSecret(Encoding.UTF8.GetBytes(secretToVerify))));
            }
        }

        public bool VerifyRegistrationToken(string registrationTokenToVerify)
        {
            if (registrationTokenToVerify == null && _registrationToken != null) return false;
            if (registrationTokenToVerify != null && _registrationToken == null) return false;

            // if there is no registrationToken and none was supplied, return true.
            if (registrationTokenToVerify == null && _registrationToken == null) return true;

            if (_registrationTokenIsHashed == false)
            {
                // registrationToken is in clear-text, so just compare the two values
                return (_registrationToken == registrationTokenToVerify);
            }
            else
            {
                // registrationToken is hashed, so calculate the hash of the supplied registrationTokenToVerify and then compare the two values.
                return (HashesAreEqual(Convert.FromBase64String(_registrationToken), HashClientRegistrationToken(Encoding.UTF8.GetBytes(registrationTokenToVerify))));
            }
        }

        public static OAuth2Client NewClient(string authServerId)
        {
            return NewClient(authServerId, null);
        }

        // if accountId is not null, this client registration is allocated in the login servers for the account (and restricted to users of that account) instead of the root login servers.
        public static OAuth2Client NewClient(string loginServerId, string accountId)
        {
            OAuth2Client resultClient = new OAuth2Client();
            resultClient._secretIsHashed = false;
            //
            ParsingHelper.ServerDetails? loginServerDetails = ParsingHelper.ExtractServerDetailsFromAccountServerId(loginServerId);
            if (loginServerDetails == null)
            {
                /* TODO: raise critical exception, or otherwise handle this error.  Should this ever actually happen? */
                throw new Exception();
            }
            resultClient._loginServerDetails = loginServerDetails.Value;
            resultClient._id = null;
            //
            resultClient._accountId = accountId;
            resultClient._accountId_IsDirty = true;
            //
            resultClient._tokenEndpointAuthMethod = OAuth2TokenEndpointAuthMethod.None;
            resultClient._tokenEndpointAuthMethod_IsDirty = true;
            //
            resultClient._redirectUris = new ListWithDirtyFlag<string>();
            resultClient._grantTypes = new ListWithDirtyFlag<OAuth2GrantType>();
            resultClient._responseTypes = new ListWithDirtyFlag<OAuth2ResponseType>();
            resultClient._scopes = new ListWithDirtyFlag<string>();
            //
            resultClient._registrationTokenIsHashed = false;
            //
            return resultClient;
        }

        private static byte[] HashClientSecret(byte[] secret)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(secret);
            }
        }

        private static byte[] HashClientRegistrationToken(byte[] registrationToken)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(registrationToken);
            }
        }

        private static bool HashesAreEqual(byte[] hash1, byte[] hash2)
        {
            if (hash1 == null && hash2 != null) return false;
            if (hash1 != null && hash2 == null) return false;
            if (hash1.Length != hash2.Length) return false;

            // CRITICAL: we iterate through all elements of the hash during comparison to protect against timing attacks.
            bool hashesMatch = true;
            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i]) hashesMatch = false;
            }
            return hashesMatch;
        }

        public async Task SaveClientAsync()
        {
            // we only support saving a local client (i.e. not updating a remote client)
            if (_isCached) throw new InvalidOperationException();

            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            bool objectIsNew = (_timeCreatedInUnixMicroseconds == null);

            int RESULT_KEY_CONFLICT = -1;
            int RESULT_DATA_CORRUPTION = -2;
            int RESULT_UPDATED_SINCE_LOAD = -3;

            // get current server time
            long newTimeUpdatedInUnixMicroseconds = await _redisClient.TimeAsync();
            if (newTimeUpdatedInUnixMicroseconds < 0)
            {
                throw new Exception("Critical Redis error!");
            }
            if (newTimeUpdatedInUnixMicroseconds < _timeUpdatedInUnixMicroseconds)
            {
                throw new Exception("Critical Redis error!");
            }

            if (objectIsNew)
            {
                // assign clientId, clientSecret, issuedAt time and clientRefreshToken
                // for non-implicit grant types: generate a clientSecret
                if ((_grantTypes.Contains(OAuth2GrantType.AuthorizationCode) && _tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None) ||
                    _grantTypes.Contains(OAuth2GrantType.ClientCredentials) ||
                    _grantTypes.Contains(OAuth2GrantType.Password))
                {
                    _secret = new string(RandomHelper.CreateRandomCharacterSequence_Readable6bit_ForIdentifiers(32));
                    _secret_IsDirty = true;
                    /* TODO: consider supporting expirations on clients */
                    _expiresAt = null;
                    _expiresAt_IsDirty = true;
                }
                _issuedAt = DateTimeOffset.UtcNow;
                // create client registration token (32-byte == 192-bit)
                /* NOTE: if we ever want to look up the registration token in the #oauth2tokens collections, we will need to start making sure the token is unique-for-server here */
                _registrationToken = _loginServerDetails.ToAccountIdServerIdIdentifierString() + "-" + (new string(RandomHelper.CreateRandomCharacterSequence_Readable6bit_ForIdentifiers(32)));
                _registrationToken_IsDirty = true;
            }

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            if (objectIsNew)
            {
                // for new clients: if a client with this client-id already exists, return 0...and we will try again.
                luaBuilder.Append(
                    "if redis.call(\"EXISTS\", KEYS[1]) == 1 then\n" +
                    "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                    "end\n");
            }
            else
            {
                // for updated: make sure that the "time-created" timestamp has not changed (i.e. that a new key has not replaced the old key)
                luaBuilder.Append("local time_created = redis.call(\"HGET\", KEYS[1], \"time-created\")\n");
                luaBuilder.Append("if time_created ~= ARGV[" + iArgument.ToString() + "] then\n" +
                    "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                    "end\n");
                arguments.Add(_timeCreatedInUnixMicroseconds.ToString());
                iArgument++;

                // for updates: make sure that our old "time-updated" timestamp has not changed
                luaBuilder.Append("local old_time_updated = redis.call(\"HGET\", KEYS[1], \"time-updated\")\n");
                luaBuilder.Append("if old_time_updated ~= ARGV[" + iArgument.ToString() + "] then\n" +
                    "  return " + RESULT_UPDATED_SINCE_LOAD.ToString() + "\n" +
                    "end\n");
                arguments.Add(_timeUpdatedInUnixMicroseconds.ToString());
                iArgument++;
            }
            //
            if (objectIsNew)
            {
                luaBuilder.Append(
                    "if redis.call(\"HSET\", KEYS[1], \"time-created\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                    "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                    "end\n");
                arguments.Add(newTimeUpdatedInUnixMicroseconds.ToString());
                iArgument++;
            }
            //
            luaBuilder.Append(
                "if redis.call(\"HSET\", KEYS[1], \"time-updated\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                "end\n");
            arguments.Add(newTimeUpdatedInUnixMicroseconds.ToString());
            iArgument++;
            //
            if (_accountId_IsDirty)
            {
                if (_accountId != null)
                {
                    // if there is an account assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"account-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_accountId);
                    iArgument++;
                }
                else
                {
                    // if the account-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"account-id\")\n");
                }
                // clear the dirty flag
                _accountId_IsDirty = false;
            }
            if (_secret_IsDirty)
            {
                if (_secret != null)
                {
                    // if there is a secret assigned to this client, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"secret-hash\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(Convert.ToBase64String(HashClientSecret(Encoding.UTF8.GetBytes(_secret))));
                    iArgument++;
                }
                else
                {
                    // if the secret has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"secret-hash\")\n");
                }
                // clear the dirty flag
                _secret_IsDirty = false;
            }
            if (objectIsNew)
            {
                // set the issued-at time
                luaBuilder.Append(
                    "if redis.call(\"HSET\", KEYS[1], \"issued-at\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                    (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                    "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                    "end\n");
                arguments.Add(_issuedAt.Value.ToUnixTimeSeconds().ToString());
                iArgument++;
            }
            // set the expires-at time
            if (_expiresAt_IsDirty)
            {
                if (_expiresAt != null)
                {
                    long expiresAtAsLong = _expiresAt.Value.ToUnixTimeSeconds();

                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"expires-at\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(expiresAtAsLong.ToString());
                    iArgument++;
                }
                else
                {
                    // if the expiration has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"expires-at\")\n");
                }
                // clear the dirty flag
                _expiresAt_IsDirty = false;
            }
            if (_softwareId_IsDirty)
            {
                luaBuilder.Append(
                    "if redis.call(\"HSET\", KEYS[1], \"software-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                    "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                    "end\n");
                arguments.Add(_softwareId);
                iArgument++;

                // clear the dirty flag
                _softwareId_IsDirty = false;
            }
            if (_softwareVersion_IsDirty)
            {
                if (_softwareVersion != null)
                {
                    // set the softwareVersion
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"software-version\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_softwareVersion);
                    iArgument++;
                }
                else
                {
                    // if the software-version has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"software-version\")\n");
                }
                // clear the dirty flag
                _softwareVersion_IsDirty = false;
            }
            // set the tokenEndpointAuthMethod
            if (_tokenEndpointAuthMethod_IsDirty)
            {
                luaBuilder.Append(
                    "if redis.call(\"HSET\", KEYS[1], \"token-endpoint-auth-method\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                    (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                    "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                    "end\n");
                arguments.Add(OAuth2Convert.ConvertTokenEndpointAuthMethodToString(_tokenEndpointAuthMethod));
                iArgument++;

                // clear the dirty flag
                _tokenEndpointAuthMethod_IsDirty = false;
            }
            //populate the set of redirect-uris
            if (_redirectUris.IsDirty)
            {
                luaBuilder.Append(objectIsNew ? "" : "redis.call(\"DEL\", KEYS[2])\n");
                foreach (string redirectUri in _redirectUris)
                {
                    luaBuilder.Append(
                        "if redis.call(\"SADD\", KEYS[2], ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[2])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(redirectUri);
                    iArgument++;
                }

                // clear the dirty flag
                _redirectUris.IsDirty = false;
            }
            // populate the set of grant-types
            if (_grantTypes.IsDirty)
            {
                luaBuilder.Append(objectIsNew ? "" : "redis.call(\"DEL\", KEYS[3])\n");
                foreach (OAuth2GrantType grantType in _grantTypes)
                {
                    luaBuilder.Append(
                        "if redis.call(\"SADD\", KEYS[3], ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[2])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[3])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(OAuth2Convert.ConvertGrantTypeToString(grantType));
                    iArgument++;
                }

                // clear the dirty flag
                _grantTypes.IsDirty = false;
            }
            // populate the set of response-types
            if (_responseTypes.IsDirty)
            {
                luaBuilder.Append(objectIsNew ? "" : "redis.call(\"DEL\", KEYS[4])\n");
                foreach (OAuth2ResponseType responseType in _responseTypes)
                {
                    luaBuilder.Append(
                        "if redis.call(\"SADD\", KEYS[4], ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[2])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[3])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[4])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(OAuth2Convert.ConvertResponseTypeToString(responseType));
                    iArgument++;
                }

                // clear the dirty flag
                _responseTypes.IsDirty = false;
            }
            // populate the set of scopes
            if (_scopes.IsDirty)
            {
                luaBuilder.Append(objectIsNew ? "" : "redis.call(\"DEL\", KEYS[5])\n");
                foreach (string scope in _scopes)
                {
                    luaBuilder.Append(
                        "if redis.call(\"SADD\", KEYS[5], ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[2])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[3])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[4])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[5])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(scope);
                    iArgument++;
                }

                // clear the dirty flag
                _scopes.IsDirty = false;
            }
            //
            if (_registrationToken_IsDirty)
            {
                if (_registrationToken != null)
                {
                    // if there is a registration token assigned to this client, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"registration-token-hash\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(Convert.ToBase64String(HashClientRegistrationToken(Encoding.UTF8.GetBytes(_registrationToken))));
                    iArgument++;
                }
                else
                {
                    // if the registration token has been removed, delete it.
                    // NOTE: this operation is technically supported by spec--but removing the ability for a client to manage a token (usually because of third-party meddling) can have some unfortunate consequences as well
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"registration-token-hash\")\n");
                }
                // clear the dirty flag
                _registrationToken_IsDirty = false;
            }
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            for (int iRetry = 0; iRetry < 1000; iRetry++)
            {
                if (objectIsNew)
                {
                    // generate a 32-byte (192-bit) client_id
                    _id = _loginServerDetails.ToAccountIdServerIdIdentifierString() + "-" + (new string(RandomHelper.CreateRandomCharacterSequence_Readable6bit_ForIdentifiers(32)));
                }
                List<string> keys = new List<string>();
                keys.Add(REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + _id);
                keys.Add(REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + _id + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_REDIRECT_URIS);
                keys.Add(REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + _id + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_GRANT_TYPES);
                keys.Add(REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + _id + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_RESPONSE_TYPES);
                keys.Add(REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + _id + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_SCOPES);
                luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);

                // NOTE: the result will contain a negative integer (error) or one (success)
                // if we were able to create a key, break out of this loop; otherwise, try generating new keys up to ten times.
                if (luaResult == 1)
                {
                    // save our "time-updated" timestamp
                    _timeUpdatedInUnixMicroseconds = newTimeUpdatedInUnixMicroseconds;

                    if (objectIsNew)
                    {
                        // save our "time-created" timestamp
                        _timeCreatedInUnixMicroseconds = newTimeUpdatedInUnixMicroseconds;

                        if (_accountId == null)
                        {
                            // if the client belongs to the entire system (and not to an account), add it to the root client collection.
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + REDIS_ASTERISK + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2CLIENTS, new string[] { _id });
                        }
                        else
                        {
                            // if the client belongs to the account (and not to the user), add it to the account's client collection.
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2CLIENTS, new string[] { _id });
                        }
                    }
                    break;
                }
                else if (luaResult == RESULT_KEY_CONFLICT)
                {
                    // key name conflict; try again
                }
                else if (luaResult == RESULT_DATA_CORRUPTION)
                {
                    // data corruption
                    throw new Exception("Critical Redis error!");
                }
                else if (luaResult == RESULT_UPDATED_SINCE_LOAD)
                {
                    // token was updated since we loaded it; we need to reload the token, make the changes again, and then attempt to save it again
                    throw new Exception("Critical Redis error!");
                }
                else
                {
                    // unknown error
                    throw new Exception("Critical Redis error!");
                }
            }

            if (luaResult < 0)
            {
                throw new Exception("Critical Redis error!");
            }
        }

        public async Task DeleteClientAsync()
        {
            // we only support saving a local client (i.e. not updating a remote client)
            if (_isCached) throw new InvalidOperationException();
            // we cannot delete a client which has not yet been created
            if (_timeCreatedInUnixMicroseconds == null) return;

            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            int RESULT_KEY_CONFLICT = -1;

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            // if the token has already been deleted, return success
            luaBuilder.Append(
                "if redis.call(\"EXISTS\", KEYS[1]) == 0 then\n" +
                "  return 1\n" +
                "end\n");
            // for deletions: make sure that the "time-created" timestamp has not changed (i.e. that a new key has not replaced the old key)
            luaBuilder.Append("local time_created = redis.call(\"HGET\", KEYS[1], \"time-created\")\n");
            luaBuilder.Append("if time_created ~= ARGV[" + iArgument.ToString() + "] then\n" +
                "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                "end\n");
            arguments.Add(_timeCreatedInUnixMicroseconds.ToString());
            iArgument++;
            //
            luaBuilder.Append(
                "redis.call(\"DEL\", KEYS[1])\n");
            // 
            // remove the token from corresponding set
            luaBuilder.Append("redis.call(\"SREM\", KEYS[2], ARGV[" + iArgument.ToString() + "])\n");
            arguments.Add(_id);
            iArgument++;
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            List<string> keys = new List<string>();
            keys.Add(REDIS_PREFIX_CLIENT + REDIS_PREFIX_SEPARATOR + _id);
            if (_accountId != null)
            {
                // index of all oauth2clients for this account
                keys.Add(REDIS_PREFIX_ACCOUNT + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2CLIENTS);
            }
            else
            {
                // index of all oauth2clients for the root
                keys.Add(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + REDIS_ASTERISK + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2CLIENTS);
            }
            luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);

            // NOTE: the result will contain a negative integer (error) or positive one (success)
            if (luaResult == 1)
            {
                // reset our server-assigned values
                _timeCreatedInUnixMicroseconds = null;
                _timeUpdatedInUnixMicroseconds = null;
                _issuedAt = null;
                _expiresAt = null;
                _registrationToken = null;
                _registrationTokenIsHashed = false;
                _secret = null;
                _secretIsHashed = false;
                _id = null;
                _isCached = false;
            }
            else if (luaResult == RESULT_KEY_CONFLICT)
            {
                // key name conflict; abort
                return;
            }
            else
            {
                // unknown error
                throw new Exception("Critical Redis error!");
            }

            if (luaResult < 0)
            {
                throw new Exception("Critical Redis error!");
            }
        }

        public string Id
        {
            get
            {
                return _id;
            }
        }

        public string Secret
        {
            get
            {
                return _secret;
            }
        }

        public bool SecretIsHashed
        {
            get
            {
                return _secretIsHashed;
            }
        }

        public string AccountId
        {
            get
            {
                return _accountId;
            }
        }

        public DateTimeOffset? IssuedAt
        {
            get
            {
                return _issuedAt;
            }
        }

        public DateTimeOffset? ExpiresAt
        {
            get
            {
                return _expiresAt;
            }
            set
            {
                if (_expiresAt != value)
                {
                    _expiresAt = value;
                    _expiresAt_IsDirty = true;
                }
            }
        }

        public string SoftwareId
        {
            get
            {
                return _softwareId;
            }
            set
            {
                if (value == null) throw new ArgumentNullException();
                if (_softwareId != value)
                {
                    _softwareId = value;
                    _softwareId_IsDirty = true;
                }
            }
        }

        public string SoftwareVersion
        {
            get
            {
                return _softwareVersion;
            }
            set
            {
                if (_softwareVersion != value)
                {
                    _softwareVersion = value;
                    _softwareVersion_IsDirty = true;
                }
            }
        }

        public OAuth2TokenEndpointAuthMethod TokenEndpointAuthMethod
        {
            get
            {
                return _tokenEndpointAuthMethod;
            }
            set
            {
                if (_tokenEndpointAuthMethod != value)
                {
                    _tokenEndpointAuthMethod = value;
                    _tokenEndpointAuthMethod_IsDirty = true;
                }
            }
        }

        public ListWithDirtyFlag<string> RedirectUris
        {
            get
            {
                return _redirectUris;
            }
        }

        public ListWithDirtyFlag<OAuth2GrantType> GrantTypes
        {
            get
            {
                return _grantTypes;
            }
        }

        public ListWithDirtyFlag<OAuth2ResponseType> ResponseTypes
        {
            get
            {
                return _responseTypes;
            }
        }

        public ListWithDirtyFlag<string> Scopes
        {
            get
            {
                return _scopes;
            }
        }

        public string RegistrationToken
        {
            get
            {
                return _registrationToken;
            }
        }

        public bool RegistrationTokenIsHashed
        {
            get
            {
                return _registrationTokenIsHashed;
            }
        }

        public Int64? TimeCreatedInUnixMicroseconds
        {
            get
            {
                return _timeCreatedInUnixMicroseconds;
            }
        }

        public Int64? TimeUpdatedInUnixMicroseconds
        {
            get
            {
                return _timeUpdatedInUnixMicroseconds;
            }
        }

        public bool IsCached
        {
            get
            {
                return _isCached;
            }
        }
    }
}
