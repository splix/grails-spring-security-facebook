package com.the6hours.grails.springsecurity.facebook

import org.springframework.web.filter.GenericFilterBean
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.context.ApplicationEventPublisher
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.Cookie
import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AuthenticationManager

/**
 * TODO
 *
 * @since 14.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class FacebookAuthCookieFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    ApplicationEventPublisher applicationEventPublisher
    String applicationId
    FacebookAuthUtils facebookAuthUtils
    AuthenticationManager authenticationManager

    void doFilter(ServletRequest servletRequest, ServletResponse response, javax.servlet.FilterChain chain) {
        HttpServletRequest request = servletRequest
        if (SecurityContextHolder.context.authentication == null) {
            logger.debug("Applying facebook auth filter")
            String cookieName = "fbs_" + applicationId

            Cookie cookie = request.cookies.find { Cookie it ->
                logger.debug("Validate cookie $it.name")
                return it.name == cookieName
            }

            if (cookie != null) {
                Map params = [:]
                cookie.value.split("&").each {
                    String[] pair = it.split("=")
                    params[pair[0]] = pair[1].decodeURL()
                }
                FacebookAuthToken token = facebookAuthUtils.build(params)
                if (token != null) {
                    Authentication authentication = authenticationManager.authenticate(token);
                    // Store to SecurityContextHolder
                    SecurityContextHolder.context.authentication = authentication;

                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContextHolder populated with FacebookAuthToken: '"
                            + SecurityContextHolder.context.authentication + "'");
                    }
                    try {
                        chain.doFilter(request, response);
                    } finally {
                        SecurityContextHolder.context.authentication = null;
                    }
                    return
                }
            } else {
                logger.debug("No cookie with name $cookieName")
            }
        } else {
            logger.debug("SecurityContextHolder not populated with FacebookAuthToken token, as it already contained: $SecurityContextHolder.context.authentication");
        }
        chain.doFilter(request, response);
    }
}
