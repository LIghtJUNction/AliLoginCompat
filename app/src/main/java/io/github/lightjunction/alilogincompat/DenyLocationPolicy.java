package io.github.lightjunction.alilogincompat;

import java.net.URI;
import java.net.URLDecoder;

final class DenyLocationPolicy {
    static boolean shouldReplace(String location) {
        if (location == null) return false;
        try {
            URI uri = new URI(location);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getRawUserInfo() != null
                    || !"bixi.alicdn.com".equalsIgnoreCase(uri.getHost())
                    || (uri.getPort() != -1 && uri.getPort() != 443)
                    || uri.getPath() == null || !uri.getPath().startsWith("/punish/")) return false;
            String query = uri.getRawQuery();
            if (query == null) return false;
            int actions = 0;
            boolean deny = false;
            for (String pair : query.split("&")) {
                String[] parts = pair.split("=", 2);
                if ("action".equals(URLDecoder.decode(parts[0], "UTF-8"))) {
                    actions++;
                    deny = parts.length == 2 && "deny".equals(URLDecoder.decode(parts[1], "UTF-8"));
                }
            }
            return actions == 1 && deny;
        } catch (Exception malformed) {
            return false;
        }
    }
}
