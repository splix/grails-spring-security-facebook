package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.apache.commons.lang.StringUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

@CompileStatic
class FacebookAuthJsonFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(this)

    FacebookAuthUtils facebookAuthUtils

    List<String> methods = ['POST']

    FacebookAuthJsonFilter(String url) {
        super(url)
    }

    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String method = request.method?.toUpperCase() ?: 'UNKNOWN'
        if (!methods.contains(method)) {
            log.error("Request method: $method, allowed only $methods")
            throw new InvalidRequestException("$method is not accepted")
        }

        FacebookAuthToken token

        if (StringUtils.isNotEmpty(request.getParameter('access_token'))) {
            String accessTokenValue = request.getParameter('access_token')
            FacebookAccessToken accessToken = facebookAuthUtils.refreshAccessToken(accessTokenValue)
            if (!accessToken) {
                throw new InvalidRequestException("Invalid access_token value (or expired)")
            }

            token = new FacebookAuthToken(accessToken: accessToken, authenticated: true)
            return authenticationManager.authenticate(token)
        }

        if (StringUtils.isNotEmpty(request.getParameter('signed_request'))) {
            token = facebookAuthUtils.build(request.getParameter('signed_request'))
        } else if (StringUtils.isNotEmpty(request.getParameter('signedRequest'))) { //TODO remove. for backward compatibility only
            token = facebookAuthUtils.build(request.getParameter('signedRequest'))
        }
        if (!token) {
            throw new InvalidRequestException("Client didn't provide any details for authorization")
        }

        authenticationManager.authenticate token
    }
}
