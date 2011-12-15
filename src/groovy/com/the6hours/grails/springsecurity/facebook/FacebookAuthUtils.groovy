package com.the6hours.grails.springsecurity.facebook

import org.apache.log4j.Logger
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import org.apache.commons.codec.binary.Base64
import org.springframework.security.authentication.BadCredentialsException
import grails.converters.JSON

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
    String applicationId

    FacebookAuthToken build(String signedRequest) {
        String[] signedRequestParts = signedRequest.split('\\.')
        if (signedRequestParts.length != 2) {
            throw new BadCredentialsException("Invalid Signed Request")
        }

        if (!verifySign(signedRequestParts[0], signedRequestParts[1])) {
            throw new BadCredentialsException("Invalid signature")
        } else {
            log.debug "Signature is ok"
        }

        String jsonData = new String(Base64.decodeBase64(signedRequestParts[1].getBytes()), 'UTF-8')

        def json = JSON.parse(jsonData)

        FacebookAuthToken token = new FacebookAuthToken(
                uid: Long.parseLong(json.user_id.toString()),
                accessToken: json.code?.toString()
        )
        token.authenticated = true
        return token
    }

    public Cookie getAuthCookie(HttpServletRequest request) {
        String cookieName = "fbsr_" + applicationId
        return request.cookies.find { Cookie it ->
            //FacebookAuthUtils.log.debug("Cookier $it.name, expected $cookieName")
            return it.name == cookieName
        }
    }

    public boolean verifySign(String sign, String payload) {
        String signer = 'HMACSHA256'
        SecretKeySpec sks = new SecretKeySpec(secret.getBytes(), signer)
        try {
            Mac mac = Mac.getInstance(signer)
            mac.init(sks)
            byte[] my = mac.doFinal(payload.getBytes())
            byte[] their = Base64.decodeBase64(sign.getBytes())
            return Arrays.equals(my, their)
        } catch (Exception e) {
            log.error("Can't validate signature", e);
            return false;
        }
    }
}
