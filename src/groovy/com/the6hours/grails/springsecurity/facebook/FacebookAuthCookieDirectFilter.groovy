package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.Cookie

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 05.07.12
 */
class FacebookAuthCookieDirectFilter extends AbstractAuthenticationProcessingFilter {

    FacebookAuthUtils facebookAuthUtils

    FacebookAuthCookieDirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = facebookAuthUtils.getAuthCookie(request)
        if (!cookie || cookie.value == null) {
            throw new InvalidCookieException("No cookie")
        }
        FacebookAuthToken token = facebookAuthUtils.build(cookie.value)
        return authenticationManager.authenticate(token)
    }
}
