using Strombus.Redis;
using Strombus.ServerShared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public class OAuth2AuthorizationCode
    {
        static RedisClient _redisClient = null;

        private const string REDIS_PREFIX_OAUTH2CODE = "oauth2code";
        private const string REDIS_PREFIX_SEPARATOR = ":";

        private string _authServerId;

        private string _id;
        private string _clientId;
        private bool _clientId_IsDirty = false;
        private string _accountId;
        private bool _accountId_IsDirty = false;
        private string _userId;
        private bool _userId_IsDirty = false;
        private string _redirectUri;
        private bool _redirectUri_IsDirty = false;
        private string _tokenId;
        private bool _tokenId_IsDirty = false;
        private bool _isUsed; // no dirty flag for isUsed, since it is set atomically

        // TTL is calculated based on the remaining # of milliseconds before expirationTime, if provided.
        private DateTimeOffset? _expirationTime;
        private bool _expirationTime_IsDirty = false;

        public enum LoadAuthCodeOptions
        {
            SearchLocal = 0x01,   // attempt to retrieve authorization codes locally
        }

        public static async Task<OAuth2AuthorizationCode> LoadAuthCodeAsync(string authCodeId)
        {
            return await LoadAuthCodeAsync(authCodeId, LoadAuthCodeOptions.SearchLocal).ConfigureAwait(false);
        }

        public static async Task<OAuth2AuthorizationCode> LoadAuthCodeAsync(string authCodeId, LoadAuthCodeOptions options)
        {
            if ((options & LoadAuthCodeOptions.SearchLocal) == LoadAuthCodeOptions.SearchLocal)
            {
                if (_redisClient == null)
                {
                    _redisClient = await Singletons.GetRedisClientAsync();
                }

                string fullyQualifiedAuthCodeKey = REDIS_PREFIX_OAUTH2CODE + REDIS_PREFIX_SEPARATOR + authCodeId;
                bool localAuthCodeExists = (await _redisClient.ExistsAsync(new string[] { fullyQualifiedAuthCodeKey }) > 0);
                if (localAuthCodeExists)
                {
                    Dictionary<string, string> authCodeDictionary = await _redisClient.HashGetAllASync<string, string, string>(fullyQualifiedAuthCodeKey);
                    long expiresInMilliseconds = await _redisClient.PttlAsync(fullyQualifiedAuthCodeKey);

                    string clientId = authCodeDictionary.ContainsKey("client-id") ? authCodeDictionary["client-id"] : null;
                    string accountId = authCodeDictionary.ContainsKey("account-id") ? authCodeDictionary["account-id"] : null;
                    if (accountId == null)
                    {
                        return null;
                    }
                    string userId = authCodeDictionary.ContainsKey("user-id") ? authCodeDictionary["user-id"] : null;
                    string redirectUri = authCodeDictionary.ContainsKey("redirect-uri") ? authCodeDictionary["redirect-uri"] : null;

                    // get "is-used" value (which, when present, indicates that the authorization code has already been submitted to the token endpoint).
                    bool isUsed = authCodeDictionary.ContainsKey("is-used");
                    // if the code is used, it may also have already been assigned a token-id; we store this in case the code is compromised before it expires (i.e. and we need to revoke the token).
                    string tokenId = authCodeDictionary.ContainsKey("token-id") ? authCodeDictionary["token-id"] : null;

                    OAuth2AuthorizationCode result = new OAuth2AuthorizationCode();
                    result._id = authCodeId;
                    result._clientId = clientId;
                    result._accountId = accountId;
                    result._userId = userId;
                    result._redirectUri = redirectUri;
                    result._isUsed = isUsed;
                    result._tokenId = tokenId;
                    if (expiresInMilliseconds >= 0)
                    {
                        result._expirationTime = DateTimeOffset.UtcNow.AddMilliseconds(expiresInMilliseconds);
                    }

                    return result;
                }
            }

            // valid auth code could not be found
            return null;
        }

        public static OAuth2AuthorizationCode NewAuthCode(string authServerId)
        {
            OAuth2AuthorizationCode result = new OAuth2AuthorizationCode();
            result._authServerId = authServerId;
            return result;
        }

        public async Task SaveAuthCodeAsync()
        {
            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            bool objectIsNew = (_id == null);

            int RESULT_KEY_CONFLICT = -1;
            int RESULT_DATA_CORRUPTION = -2;

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            if (objectIsNew)
            {
                // for new authorization codes: if a token with this authcode-id already exists, return 0...and we will try again.
                luaBuilder.Append(
                    "if redis.call(\"EXISTS\", KEYS[1]) == 1 then\n" +
                    "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                    "end\n");
            }
            if (_clientId_IsDirty)
            {
                if (_clientId != null)
                {
                    // if there is a client assigned to this authorization code, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"client-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_clientId);
                    iArgument++;
                }
                else
                {
                    // if the client-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"client-id\")\n");
                }
                // clear the dirty flag
                _clientId_IsDirty = false;
            }
            if (_accountId_IsDirty)
            {
                if (_accountId != null)
                {
                    // if there is an account assigned to this authorization code, save it.
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
            if (_userId_IsDirty)
            {
                if (_userId != null)
                {
                    // if there is a user assigned to this authorization code, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"user-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_userId);
                    iArgument++;
                }
                else
                {
                    // if the user-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"user-id\")\n");
                }
                // clear the dirty flag
                _userId_IsDirty = false;
            }
            if (_redirectUri_IsDirty)
            {
                if (_redirectUri != null)
                {
                    // if there is a redirect-uri assigned to this authorization code, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"redirect-uri\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_redirectUri);
                    iArgument++;
                }
                else
                {
                    // if the redirect-uri has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"redirect-uri\")\n");
                }
                // clear the dirty flag
                _redirectUri_IsDirty = false;
            }
            // NOTE: when a token is assigned to an authorization code, we re-save the code with the token (in case the same token is reused...in which case we can revoke the already-allocated token)
            if (_tokenId_IsDirty)
            {
                if (_tokenId != null)
                {
                    // if there is a token assigned to this authorization code, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"token-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return 0\n" +
                        "end\n");
                    arguments.Add(_tokenId);
                    iArgument++;
                }
                else
                {
                    // if the token-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"token-id\")\n");
                }
                // clear the dirty flag
                _tokenId_IsDirty = false;
            }
            if (_expirationTime_IsDirty)
            {
                if (_expirationTime != null)
                {
                    double expirationMilliseconds = _expirationTime.Value.Subtract(DateTimeOffset.UtcNow).TotalMilliseconds;
                    if (expirationMilliseconds >= 0)
                    {
                        long expirationMillisecondsAsWholeNumber = (long)expirationMilliseconds;

                        // if there is an expiration time assigned to this authorization code, set it.
                        luaBuilder.Append(
                            "if redis.call(\"PEXPIRE\", KEYS[1], ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                            (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                            "  return 0\n" +
                            "end\n");
                        arguments.Add(expirationMillisecondsAsWholeNumber.ToString());
                        iArgument++;
                    }
                }
                else
                {
                    // if the expiration has been removed, delete it.
                    luaBuilder.Append(
                        "if redis.call(\"PERSIST\", KEYS[1]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return 0\n" +
                        "end\n");
                }
                // clear the dirty flag
                _expirationTime_IsDirty = false;
            }
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            for (int iRetry = 0; iRetry < (objectIsNew ? 1000 : 1); iRetry++)
            {
                if (objectIsNew)
                {
                    // generate a 24-byte (144-bit) token_id
                    _id = _authServerId + "-" + (new string(RandomHelper.CreateRandomCharacterSequence_Readable6bit_ForIdentifiers(24)));
                }
                List<string> keys = new List<string>();
                keys.Add(REDIS_PREFIX_OAUTH2CODE + REDIS_PREFIX_SEPARATOR + _id);
                luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);
                //if we were able to create a key, break out of this loop; otherwise, try generating new keys up to ten times.
                if (luaResult == 1)
                {
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

        public async Task<bool> MarkAsUsedAsync()
        {
            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            bool objectIsNew = (_id == null);

            int RESULT_DATA_CORRUPTION = -2;
            int RESULT_DOES_NOT_EXIST = -4;
            int RESULT_ALREADY_USED = -5;

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            if (objectIsNew)
            {
                // for new authorization codes: if a token with this authcode-id does not already exist, return 0 and we will simply abort.
                luaBuilder.Append(
                    "if redis.call(\"EXISTS\", KEYS[1]) == 0 then\n" +
                    "  return " + RESULT_DOES_NOT_EXIST.ToString() + "\n" +
                    "end\n");
            }
            // make sure that this authorization code is not already "used"; if it is, abort.
            luaBuilder.Append(
                "if redis.call(\"HEXISTS\", KEYS[1], \"is-used\") == 1 then\n" +
                "  return " + RESULT_ALREADY_USED.ToString() + "\n" +
                "end\n");
            arguments.Add("1");
            iArgument++;
            // mark this authorization code as "used" (which indicates that it has been submitted to the token endpoint)
            luaBuilder.Append(
                "if redis.call(\"HSET\", KEYS[1], \"is-used\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                "end\n");
            arguments.Add("1");
            iArgument++;
            // if the authorization code expired while we were updating the flag (and therefore we RE-CREATED the key), delete the accidentally-just-recreated key
            luaBuilder.Append(
                "if redis.call(\"PTTL\", KEYS[1]) == -1 then\n" +
                "  redis.call(\"DEL\", KEYS[1])\n" +
                "  return " + RESULT_DOES_NOT_EXIST.ToString() + "\n" +
                "end\n");
            //
            luaBuilder.Append("return 1\n");

            List<string> keys = new List<string>();
            keys.Add(REDIS_PREFIX_OAUTH2CODE + REDIS_PREFIX_SEPARATOR + _id);
            long luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);

            if (luaResult == 1)
            {
                _isUsed = true;
                return true;
            }
            else
            {
                return false;
            }
        }

        public async Task DeleteTokenAsync()
        {
            // we cannot delete a code which has not yet been created
            if (_id == null) return;

            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            int RESULT_KEY_CONFLICT = -1;

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            //int iArgument = 1;
            // if the code has already been deleted, return success
            luaBuilder.Append(
                "if redis.call(\"EXISTS\", KEYS[1]) == 0 then\n" +
                "  return 1\n" +
                "end\n");
            //
            luaBuilder.Append(
                "redis.call(\"DEL\", KEYS[1])\n");
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            List<string> keys = new List<string>();
            keys.Add(REDIS_PREFIX_OAUTH2CODE + REDIS_PREFIX_SEPARATOR + _id);
            luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);

            // NOTE: the result will contain a negative integer (error) or positive one (success)
            if (luaResult == 1)
            {
                // reset our server-assigned values
                _id = null;
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

        public string AccountId
        {
            get
            {
                return _accountId;
            }
            set
            {
                if (_accountId != value)
                {
                    _accountId = value;
                    _accountId_IsDirty = true;
                };
            }
        }

        public string ClientId
        {
            get
            {
                return _clientId;
            }
            set
            {
                if (_clientId != value)
                {
                    _clientId = value;
                    _clientId_IsDirty = true;
                }
            }
        }

        public string UserId
        {
            get
            {
                return _userId;
            }
            set
            {
                if (_userId != value)
                {
                    _userId = value;
                    _userId_IsDirty = true;
                }
            }
        }

        public string RedirectUri
        {
            get
            {
                return _redirectUri;
            }
            set
            {
                if (_redirectUri != value)
                {
                    _redirectUri = value;
                    _redirectUri_IsDirty = true;
                }
            }
        }

        public bool IsUsed
        {
            get
            {
                return _isUsed;
            }
        }

        public string TokenId
        {
            get
            {
                return _tokenId;
            }
            set
            {
                if (_tokenId != value)
                {
                    _tokenId = value;
                    _tokenId_IsDirty = true;
                }
            }
        }

        public DateTimeOffset? ExpirationTime
        {
            get
            {
                return _expirationTime;
            }
            set
            {
                if (_expirationTime != value)
                {
                    _expirationTime = value;
                    _expirationTime_IsDirty = true;
                }
            }
        }
    }
}
