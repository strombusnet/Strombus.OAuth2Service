using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public enum OAuth2GrantType
    {
        AuthorizationCode, // default (use authorization code flow)
        Implicit,          // implicit flow (for web browsers, etc.)
        Password,          // username/password login (we only allow this for trusted first-party clients)
        ClientCredentials, // server to server flow, using manually-entered OAuth2 credentials
        RefreshToken       // refresh grant
    }
}
