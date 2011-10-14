package com.the6hours.grails.springsecurity.facebook

import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.lang.StringUtils
import org.apache.log4j.Logger

/**
 * TODO
 *
 * @since 14.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class FacebookAuthUtils {

    private static def log = Logger.getLogger(this)

    String apiKey
    String secret

    /**
    * List of parameters that are signed by facebook
    */
    List<String> fbParams = ["access_token", "secret", "uid", "expires", "session_key", "base_domain"]

    FacebookAuthToken build(Map params) {
        String authToken = params["access_token"];

        if (StringUtils.isEmpty(authToken)) {
            return null
        }

        StringBuilder buf = new StringBuilder()
        String[] names = params.keySet().findAll { String it ->
            return fbParams.contains(it)
        }
        names.sort().each { String param ->
            buf.append(param).append('=').append(params[param])
        }
        buf.append(secret)

        String expectedSignature = DigestUtils.md5Hex(buf.toString())
        String sig = params["sig"]

        if (!expectedSignature.equals(sig)) {
            log.warn "Signature for [$buf] is $expectedSignature, but expected signature is $sig"
            return null
        } else {
            log.debug "Signature is ok"
        }

        FacebookAuthToken token = new FacebookAuthToken(
                uid: Long.parseLong(params["uid"].toString()),
                secret: params["secret"],
                session: params["session_key"],
                accessToken: params['access_token']
        )
        token.authenticated = true
        return token
    }
}
