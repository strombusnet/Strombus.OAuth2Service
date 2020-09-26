using Strombus.Redis;
using Strombus.ServerShared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public class OAuth2InitialAccessToken
    {
        static RedisClient _redisClient = null;

        private const string REDIS_PREFIX_ACCOUNT = "account";
        private const string REDIS_PREFIX_LOGIN_SERVICE = "login-service";
        private const string REDIS_PREFIX_OAUTH2_TOKEN = "oauth2token";
        private const string REDIS_PREFIX_SEPARATOR = ":";
        //
        private const string REDIS_BRACKET_LEFT = "[";
        private const string REDIS_BRACKET_RIGHT = "]";
        private const string REDIS_ASTERISK = "*";
        private const string REDIS_ATSIGN = "@";
        private const string REDIS_SLASH = "/";
        //
        private const string REDIS_SUFFIX_OAUTH2TOKENS = "oauth2tokens";
        private const string REDIS_SUFFIX_SEPARATOR = "#";

        private const string TOKEN_TYPE_INITIAL_ACCESS_TOKEN = "initial";

        private ParsingHelper.ServerDetails _loginServerDetails; // the server details of the OAuth2 service (e.g. accountId, serverType, serverId)

        private string _id;
        private string _softwareId;
        private bool _softwareId_IsDirty = false;
        private string _accountId;
        private bool _accountId_IsDirty = false;
        private Int64? _timeCreatedInUnixMicroseconds; // null for new objects; otherwise the creation timestamp when the object was saved by redis
        private Int64? _timeUpdatedInUnixMicroseconds; // null for new objects; otherwise the last timestamp that the object was saved by redis
        private bool _isCached;

        private OAuth2InitialAccessToken()
        {
        }

        public enum LoadTokenOptions
        {
            LocalTokens = 0x01,   // attempt to retrieve token locally
        }

        public static async Task<OAuth2InitialAccessToken> LoadInitialAccessTokenAsync(string tokenId)
        {
            // default operation: attempt to retrieve the token from our peers or children if necessary--but do not cache the token (since caching requires invalidation notification subscriptions)
            return await LoadInitialAccessTokenAsync(tokenId, LoadTokenOptions.LocalTokens /* | LoadTokenOptions.PeerTokens | LoadTokenOptions.ChildTokens */).ConfigureAwait(false);
        }

        public static async Task<OAuth2InitialAccessToken> LoadInitialAccessTokenAsync(string tokenId, LoadTokenOptions options)
        {
            if ((options & LoadTokenOptions.LocalTokens) == LoadTokenOptions.LocalTokens)
            {
                if (_redisClient == null)
                {
                    _redisClient = await Singletons.GetRedisClientAsync();
                }

                string fullyQualifiedTokenKey = REDIS_PREFIX_OAUTH2_TOKEN + REDIS_PREFIX_SEPARATOR + tokenId;
                bool localTokenExists = (await _redisClient.ExistsAsync(new string[] { fullyQualifiedTokenKey }) > 0);
                if (localTokenExists)
                {
                    Dictionary<string, string> tokenDictionary = await _redisClient.HashGetAllASync<string, string, string>(fullyQualifiedTokenKey);

                    string tokenType = tokenDictionary.ContainsKey("type") ? tokenDictionary["type"] : null;
                    if (tokenType == null || tokenType != TOKEN_TYPE_INITIAL_ACCESS_TOKEN)
                    {
                        return null;
                    }

                    string tokenIsCachedAsString = tokenDictionary.ContainsKey("cached") ? tokenDictionary["cached"] : null;
                    bool tokenIsCached = (tokenIsCachedAsString != null && tokenIsCachedAsString != "0");

                    string timeCreatedAsString = tokenDictionary.ContainsKey("time-created") ? tokenDictionary["time-created"] : null;
                    Int64? timeCreatedInUnixMicroseconds = null;
                    Int64 timeCreatedAsInt64;
                    if (timeCreatedAsString != null && Int64.TryParse(timeCreatedAsString, out timeCreatedAsInt64))
                    {
                        timeCreatedInUnixMicroseconds = timeCreatedAsInt64;
                    }

                    string timeUpdatedAsString = tokenDictionary.ContainsKey("time-updated") ? tokenDictionary["time-updated"] : null;
                    Int64? timeUpdatedInUnixMicroseconds = null;
                    Int64 timeUpdatedAsInt64;
                    if (timeUpdatedAsString != null && Int64.TryParse(timeUpdatedAsString, out timeUpdatedAsInt64))
                    {
                        timeUpdatedInUnixMicroseconds = timeUpdatedAsInt64;
                    }

                    OAuth2InitialAccessToken resultToken = new OAuth2InitialAccessToken();
                    resultToken._softwareId = tokenDictionary.ContainsKey("software-id") ? tokenDictionary["software-id"] : null;
                    if (resultToken._softwareId == null)
                    {
                        return null;
                    }
                    resultToken._accountId = tokenDictionary.ContainsKey("account-id") ? tokenDictionary["account-id"] : null;

                    // if our result token could be loaded, populate the default fields common to all OAuth2Tokens.
                    resultToken._id = tokenId;
                    ParsingHelper.ServerDetails? loginServerDetails = ParsingHelper.ExtractServerDetailsFromAccountServerIdIdentifier(tokenId);
                    if (loginServerDetails == null)
                    {
                        throw new Exception();
                    }
                    resultToken._loginServerDetails = loginServerDetails.Value;
                    resultToken._isCached = tokenIsCached;
                    resultToken._timeCreatedInUnixMicroseconds = timeCreatedInUnixMicroseconds;
                    resultToken._timeUpdatedInUnixMicroseconds = timeUpdatedInUnixMicroseconds;

                    return resultToken;
                }
            }

            // valid token could not be found
            return null;
        }

        public async Task SaveTokenAsync()
        {
            // we only support saving a local token (i.e. not updating a remote token)
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

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            if (objectIsNew)
            {
                // for new tokens: if a token with this token-id already exists, return 0.
                luaBuilder.Append(
                    "if redis.call(\"EXISTS\", KEYS[1]) == 1 then\n" +
                    "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                    "end\n");
            }
            else
            {
                // for updated: make sure that the "time-created" timestamp has no changed (i.e. that a new key has not replaced the old key)
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
                    "if redis.call(\"HSET\", KEYS[1], \"type\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                    (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                    "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                    "end\n");
                arguments.Add(TOKEN_TYPE_INITIAL_ACCESS_TOKEN);
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
            if (_softwareId_IsDirty)
            {
                if (_softwareId != null)
                {
                    // if there is a software-id assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"software-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_softwareId);
                    iArgument++;
                }
                else
                {
                    // if the software-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"software-id\")\n");
                }
                // clear the dirty flag
                _softwareId_IsDirty = false;
            }
            //
            if (_accountId_IsDirty)
            {
                if (_accountId != null)
                {
                    // if there is an account-id assigned to this token, save it.
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
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            for (int iRetry = 0; iRetry < 1000; iRetry++)
            {
                if (objectIsNew)
                {
                    // generate a new 32-byte (192-bit) token_id
                    _id = _loginServerDetails.ToAccountIdServerIdIdentifierString() + "-" + (new string(RandomHelper.CreateRandomCharacterSequence_Readable6bit_ForIdentifiers(32)));
                }
                List<string> keys = new List<string>();
                keys.Add(REDIS_PREFIX_OAUTH2_TOKEN + REDIS_PREFIX_SEPARATOR + _id);
                luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);
                
                // NOTE: the result will contain a negative integer (error) or one (success)
                //if we were able to create a key, break out of this loop; otherwise, try generating new keys up to 1000 times.
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
                            // if the token belongs to the entire system (and not to an account), add it to the root token collection.
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + REDIS_ASTERISK + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS, new string[] { _id });
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + REDIS_ASTERISK + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS + REDIS_BRACKET_LEFT + "type" + REDIS_ATSIGN + "initial" + REDIS_BRACKET_RIGHT, new string[] { _id });
                        }
                        else
                        {
                            // if the token belongs to the account (and not to the user), add it to the account's token collection.
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS, new string[] { _id });
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS + REDIS_BRACKET_LEFT + "type" + REDIS_ATSIGN + "initial" + REDIS_BRACKET_RIGHT, new string[] { _id });
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

        public async Task DeleteTokenAsync()
        {
            // we only support saving a local token (i.e. not updating a remote token)
            if (_isCached) throw new InvalidOperationException();
            // we cannot delete a token which has not yet been created
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
            // for deletions: make sure that the "time-created" timestamp has no changed (i.e. that a new key has not replaced the old key)
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
            // remove the token from corresponding sets (filtered and non-filtered indexes)
            luaBuilder.Append("redis.call(\"SREM\", KEYS[2], ARGV[" + iArgument.ToString() + "])\n");
            luaBuilder.Append("redis.call(\"SREM\", KEYS[3], ARGV[" + iArgument.ToString() + "])\n");
            arguments.Add(_id);
            iArgument++;
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            List<string> keys = new List<string>();
            keys.Add(REDIS_PREFIX_OAUTH2_TOKEN + REDIS_PREFIX_SEPARATOR + _id);
            if (_accountId != null)
            {
                // index of all oauth2tokens for this account
                keys.Add(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS);
                // index of initial access oauth2tokens for this account
                keys.Add(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS + REDIS_BRACKET_LEFT + "type" + REDIS_ATSIGN + "initial" + REDIS_BRACKET_RIGHT);
            }
            else
            {
                // index of all oauth2tokens for the root
                keys.Add(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + REDIS_ASTERISK + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS);
                // index of initial access oauth2tokens for the root
                keys.Add(REDIS_PREFIX_LOGIN_SERVICE + REDIS_PREFIX_SEPARATOR + REDIS_ASTERISK + REDIS_SLASH + _loginServerDetails.ServerId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS + REDIS_BRACKET_LEFT + "type" + REDIS_ATSIGN + "initial" + REDIS_BRACKET_RIGHT);
            }
            luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);

            // NOTE: the result will contain a negative integer (error) or positive one (success)
            if (luaResult == 1)
            {
                // reset our server-assigned values
                _timeCreatedInUnixMicroseconds = null;
                _timeUpdatedInUnixMicroseconds = null;
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

        public static OAuth2InitialAccessToken NewToken(string loginServerId)
        {
            ParsingHelper.ServerDetails? loginServerDetails = ParsingHelper.ExtractServerDetailsFromAccountServerId(loginServerId);
            if (loginServerDetails == null)
            {
                throw new Exception();
            }

            OAuth2InitialAccessToken result = new OAuth2InitialAccessToken()
            {
                _loginServerDetails = loginServerDetails.Value,
                _id = null,
                _softwareId = null,
                _accountId = null,
                _timeUpdatedInUnixMicroseconds = null,
                _isCached = false,
            };
            return result;
        }


        public string Id
        {
            get
            {
                return _id;
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
                if (_softwareId != value)
                {
                    _softwareId = value;
                    _softwareId_IsDirty = true;
                }
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
                }
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
