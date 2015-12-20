package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean

/**
 * TODO
 *
 * @since 14.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
@CompileStatic
class FacebookAuthCookieTransparentFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    ApplicationEventPublisher applicationEventPublisher
    FacebookAuthUtils facebookAuthUtils
    AuthenticationManager authenticationManager
    String logoutUrl = '/j_spring_security_logout'
    String forceLoginParameter
    String filterProcessUrl

    void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        HttpServletRequest request = (HttpServletRequest)req
        HttpServletResponse response = (HttpServletResponse)res
        String url = request.requestURI.substring(request.contextPath.length())
        logger.debug("Processing url: $url")
        if (url != logoutUrl &&
                  (!SecurityContextHolder.context.authentication ||
                      (forceLoginParameter && request.getParameter(forceLoginParameter) == 'true'))) {
            logger.debug("Applying facebook auth filter")
            assert facebookAuthUtils
            Cookie cookie = facebookAuthUtils.getAuthCookie(request)
            if (cookie) {
                if (processCookie(cookie, request, response, chain)) {
                    return
                }
            }
            else {
                logger.debug("No auth cookie")
            }
        }
        else {
            logger.debug("SecurityContextHolder not populated with FacebookAuthToken token, as it already contained: $SecurityContextHolder.context.authentication");
        }

        //when not authenticated, dont have auth cookie or bad credentials
        chain.doFilter(request, response)
    }

    protected boolean processCookie(Cookie cookie, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
        try {
            FacebookAuthToken token = facebookAuthUtils.build(cookie.value)
            if (!token) {
                return false
            }

            Authentication authentication
            try {
                authentication = authenticationManager.authenticate(token)
            }
            catch (Throwable t) {
                logger.warn("Error during authentication. Skipping. Message: $t.message")
            }
            if (authentication?.authenticated) {
                // Store to SecurityContextHolder
                SecurityContextHolder.context.authentication = authentication

                if (logger.debugEnabled) {
                    logger.debug("SecurityContextHolder populated with FacebookAuthToken: '$SecurityContextHolder.context.authentication'");
                }
                try {
                    chain.doFilter(request, response)
                    return true
                }
                finally {
                    SecurityContextHolder.context.authentication = null
                }
            }
        }
        catch (BadCredentialsException e) {
            logger.info("Invalid cookie, skip. Message was: $e.message")
        }

        false
    }
}
