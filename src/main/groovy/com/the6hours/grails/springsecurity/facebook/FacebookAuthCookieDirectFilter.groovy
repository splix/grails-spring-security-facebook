package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 05.07.12
 */
@CompileStatic
class FacebookAuthCookieDirectFilter extends AbstractAuthenticationProcessingFilter {

    FacebookAuthUtils facebookAuthUtils

    FacebookAuthCookieDirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = facebookAuthUtils.getAuthCookie(request)
        if (!cookie || !cookie.value) {
            throw new InvalidCookieException("No cookie")
        }
        authenticationManager.authenticate facebookAuthUtils.build(cookie.value)
    }
}
