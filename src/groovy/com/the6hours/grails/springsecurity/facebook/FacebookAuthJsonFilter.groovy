package com.the6hours.grails.springsecurity.facebook

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication
import org.apache.commons.lang.StringUtils
import org.apache.commons.codec.digest.*
import org.apache.log4j.Logger


public class FacebookAuthJsonFilter extends AbstractAuthenticationProcessingFilter {

    private static def log = Logger.getLogger(this)

    FacebookAuthUtils facebookAuthUtils

    List<String> methods = ['POST']

    def FacebookAuthJsonFilter(String url) {
        super(url)
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String method = request.method?.toUpperCase() ?: 'UNKNOWN'
        if (!methods.contains(method)) {
            log.error("Request method: $method, allowed only $methods")
            throw new InvalidRequestException("$method is not accepted")
        }

        FacebookAuthToken token = null

        if (StringUtils.isNotEmpty(request.getParameter('access_token'))) {
            String accessTokenValue = request.getParameter('access_token')
            FacebookAccessToken accessToken = facebookAuthUtils.refreshAccessToken(accessTokenValue)
            if (accessToken != null) {
                token = new FacebookAuthToken(
                        accessToken: accessToken,
                        authenticated: true
                )
                Authentication authentication = getAuthenticationManager().authenticate(token);
                return authentication
            } else {
                throw new InvalidRequestException("Invalid access_token value (or expired)")
            }
        }

        if (StringUtils.isNotEmpty(request.getParameter('signed_request'))) {
            token = facebookAuthUtils.build(request.getParameter('signed_request'))
        } else if (StringUtils.isNotEmpty(request.getParameter('signedRequest'))) { //TODO remove. for backward compatibility only
            token = facebookAuthUtils.build(request.getParameter('signedRequest'))
        }
        if (token != null) {
            Authentication authentication = getAuthenticationManager().authenticate(token);
            return authentication
        }

        throw new InvalidRequestException("Client didn't provide any details for authorization")
    }
	
}