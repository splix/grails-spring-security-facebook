package com.the6hours.grails.springsecurity.facebook

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication
import org.apache.commons.lang.StringUtils
import org.apache.commons.codec.digest.*
import org.apache.log4j.Logger


public class FacebookAuthDirectFilter extends AbstractAuthenticationProcessingFilter {

    private static def log = Logger.getLogger(this)

    FacebookAuthUtils facebookAuthUtils

    def FacebookAuthDirectFilter(String url) {
        super(url)
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        Map params = [:]
        request.getParameterNames().each {
            params[it] = request.getParameter(it)
        }
        FacebookAuthToken token = facebookAuthUtils.build(params)
        if (token != null) {
            Authentication authentication = getAuthenticationManager().authenticate(token);
            return authentication
        }
        return null
    }
	
}