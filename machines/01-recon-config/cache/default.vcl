vcl 4.1;

backend default {
    .host = "app";
    .port = "5000";
}

sub vcl_recv {
    if (req.url ~ "^/cached/") {
        unset req.http.Cookie;
        return (hash);
    }
    return (pass);
}

# WSTG-CONF-16: the cache key is the URL alone. Host and X-Forwarded-Host are
# not part of the key, so a response keyed on an attacker-supplied header is
# served to every subsequent visitor of the same URL.
sub vcl_hash {
    hash_data(req.url);
    return (lookup);
}

sub vcl_backend_response {
    if (bereq.url ~ "^/cached/") {
        set beresp.ttl = 120s;
        set beresp.grace = 0s;
        unset beresp.http.Set-Cookie;
    }
    return (deliver);
}

sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    set resp.http.X-Cache-Hits = obj.hits;
    return (deliver);
}