package com.the6hours.grails.springsecurity.facebook

import org.apache.log4j.Logger
import org.codehaus.groovy.grails.web.json.JSONElement

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import org.apache.commons.codec.binary.Base64
import org.springframework.security.authentication.BadCredentialsException
import grails.converters.JSON
import java.util.concurrent.TimeUnit
import org.codehaus.groovy.grails.web.json.JSONException
import org.codehaus.groovy.grails.web.mapping.LinkGenerator

/**
 * TODO
 *
 * @since 14.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class FacebookAuthUtils {

    private static def log = Logger.getLogger(this)

    private static Random RND = new Random()
    private int seq = 0

    String apiKey
    String secret
    String applicationId

    List<String> filterTypes = []
    List<String> requiredPermissions = []

    FacebookAuthToken build(String signedRequest) {
        if (!signedRequest) {
            return null
        }
        JSONElement json = extractSignedJson(signedRequest)

        String code = json.code?.toString()

        FacebookAuthToken token = new FacebookAuthToken(
                uid: Long.parseLong(json.user_id.toString()),
                code: code
        )
        token.authenticated = true
        return token
    }

    JSONElement extractSignedJson(String signedRequest) {
        String[] signedRequestParts = signedRequest.split('\\.')
        if (signedRequestParts.length != 2) {
            throw new BadCredentialsException("Invalid Signed Request")
        }

        String jsonData = new String(Base64.decodeBase64(signedRequestParts[1].getBytes()), 'UTF-8')
        jsonData = jsonData.trim()
        def json
        try {
            if (!jsonData.endsWith('}')) {
                log.info("Seems that Facebook cookie contains corrupted value. SignedRequest: ${signedRequestParts[1]}")
                jsonData = jsonData + '}'
            }
            json = JSON.parse(jsonData)
        } catch (JSONException e) {
            log.error("Cannot parse Facebook cookie. If you're sure that it should be valid cookie, please send '${signedRequestParts[1]}' to plugin author (igor@artamonov.ru)", e)
            throw new BadCredentialsException("Invalid cookie format")
        }

        if (json.algorithm != 'HMAC-SHA256') {
            throw new BadCredentialsException("Unknown hashing algorithm: $json.algorithm")
        }

        //log.debug("Payload: $jsonData")

        if (!verifySign(signedRequestParts[0], signedRequestParts[1])) {
            throw new BadCredentialsException("Invalid signature")
        } else {
            //log.debug "Signature is ok"
        }
        return json
    }

    public Cookie getAuthCookie(HttpServletRequest request) {
        String cookieName = "fbsr_" + applicationId
        return request.cookies.find { Cookie it ->
            //FacebookAuthUtils.log.debug("Cookie $it.name, expected $cookieName")
            return it.name == cookieName
        }
    }

    long loadUserUid(String accessToken) {
        String loadUrl = "https://graph.facebook.com/me?access_token=${URLEncoder.encode(accessToken, 'UTF-8')}"
        try {
            URL url = new URL(loadUrl)
            def json = JSON.parse(url.readLines().first())
            return json.id as Long
        } catch (IOException e) {
            log.error("Can't read data from Facebook", e)
        } catch (JSONException e) {
            log.error("Invalid response", e)
        }
        return -1
    }

    FacebookAccessToken refreshAccessToken(String existingAccessToken) {
        Map params = [
                client_id: applicationId,
                client_secret: secret,
                grant_type: 'fb_exchange_token',
                fb_exchange_token: existingAccessToken
        ]
        String authUrl = "https://graph.facebook.com/oauth/access_token?" + encodeParams(params)
        return requestAccessToken(authUrl)
    }

    FacebookAccessToken getAccessToken(String code, String redirectUri = '') {
        if (redirectUri == null) {
            redirectUri = ''
        }
        Map params = [
                client_id: applicationId,
                redirect_uri: redirectUri,
                client_secret: secret,
                code: code
        ]
        String authUrl = "https://graph.facebook.com/oauth/access_token?" + encodeParams(params)
        return requestAccessToken(authUrl)
    }

    FacebookAccessToken requestAccessToken(String authUrl) {
        try {
            URL url = new URL(authUrl)
            String response = url.readLines().first()
            //println "AccessToken response: $response"
            Map data = [:]
            response.split('&').each {
                String[] kv = it.split('=')
                if (kv.length != 2) {
                    log.warn("Invalid response part: $it")
                } else {
                    data[kv[0]] = kv[1]
                }
            }
            FacebookAccessToken token = new FacebookAccessToken()
            if (data.access_token) {
                token.accessToken = data.access_token
            } else {
                log.error("No access_token in response: $response")
            }
            if (data.expires) {
                if (data.expires =~ /^\d+$/) {
                    token.expireAt = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(Long.parseLong(data.expires)))
                } else {
                    log.warn("Invalid 'expires' value: $data.expires")
                }
            } else {
              log.error("No expires in response: $response")
            }
            //log.debug("Got AccessToken: $token")
            return token
        } catch (IOException e) {
            log.error("Can't read data from Facebook", e)
            return null
        }
    }

    boolean verifySign(String sign, String payload) {
        if (sign == null) {
            log.error("Empty signature")
            return false
        }
        if (payload == null) {
            log.error("Empty payload")
            return false
        }
        String signer = 'HMACSHA256'
        //log.debug("Secret $secret")
        SecretKeySpec sks = new SecretKeySpec(secret.getBytes(), signer)
        //log.debug("Payload1: `$payload`")
        payload = payload.replaceAll("-", "+").replaceAll("_", "/").trim()
        //log.debug("Payload2: `$payload`")
        sign = sign.replaceAll("-", "+").replaceAll("_", "/")
        try {
            Mac mac = Mac.getInstance(signer)
            mac.init(sks)
            byte[] my = mac.doFinal(payload.getBytes('UTF-8'))
            byte[] their = Base64.decodeBase64(sign.getBytes('UTF-8'))
            //log.info("My: ${new String(Base64.encodeBase64(my, false))}, their: ${new String(Base64.encodeBase64(their))} / $sign")
            return Arrays.equals(my, their)
        } catch (Exception e) {
            log.error("Can't validate signature", e);
            return false;
        }
    }

    String prepareRedirectUrl(String authPath, List scope = []) {
        if (seq >= Integer.MAX_VALUE - 10000) {
            seq = 0
        }
        Map data = [
                client_id: applicationId,
                redirect_uri:  authPath,
                scope: scope.join(','),
                state: [seq++, RND.nextInt(1000000)].collect {Integer.toHexString(it)}.join('-')
        ]
        log.debug("Redirect to ${data.redirect_uri}")
        String url = "https://www.facebook.com/dialog/oauth?" + encodeParams(data)
        return url
    }

    private String encodeParams(Map params) {
        return params.entrySet().each { Map.Entry<String, Object> it ->
            [
                    URLEncoder.encode(it.key, 'UTF-8'),
                    URLEncoder.encode(it.value ? it.value.toString() : '', 'UTF-8'),
            ].join('=')
        }.join('&')
    }
}
