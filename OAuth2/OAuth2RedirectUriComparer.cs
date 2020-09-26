using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Strombus.OAuth2Service.OAuth2
{
    public class OAuth2RedirectUriComparer : IEqualityComparer<string>
    {
        public bool Equals(string x, string y)
        {
            // if both URIs are true, they match.
            if (x == null && y == null) return true;
            // if one URI is null and the other is non-null, they do not match.
            if (x == null && y != null) return false;
            if (x != null && y == null) return false;

            // now, with two non-null strings, try to create URI objects from each of the URI strings; if that fails, assume that they cannot match.
            Uri uriX, uriY;
            if (!Uri.TryCreate(x, UriKind.Absolute, out uriX)) return false;
            if (!Uri.TryCreate(y, UriKind.Absolute, out uriY)) return false;

            // return false if the scheme or hostname do not match (while permitting differences in case for these elements)
            if (uriX.Scheme.ToLowerInvariant() != uriY.Scheme.ToLowerInvariant()) return false;
            if (uriX.Host.ToLowerInvariant() != uriY.Host.ToLowerInvariant()) return false;
            // return false if the port # does not match.
            if (uriX.Port != uriY.Port) return false;
            // return false if the path or query does not match.
            if (uriX.PathAndQuery != uriY.PathAndQuery) return false;
            // return false if the uri contains a hash value
            if (uriX.Fragment != null && uriX.Fragment != string.Empty) return false;
            if (uriY.Fragment != null && uriY.Fragment != string.Empty) return false;

            // if all those tests passed, then return true (i.e. the uris are equal)
            return true;
        }

        public int GetHashCode(string obj)
        {
            return obj.GetHashCode();
        }
    }
}
