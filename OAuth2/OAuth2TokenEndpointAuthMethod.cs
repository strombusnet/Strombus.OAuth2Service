using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public enum OAuth2TokenEndpointAuthMethod
    {
        None,              // public client (no client secret; does not use token endpoint)
        ClientSecretBasic, // default (use bearer token in Authorization header)
        ClientSecretPost,  // use bearer token in HTTP POST parameter
    }
}
