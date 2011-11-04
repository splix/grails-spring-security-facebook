package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.web.authentication.logout.LogoutHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import javax.servlet.http.Cookie
import org.apache.log4j.Logger

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 04.11.11
 */
class FacebookAuthCookieLogoutHandler implements LogoutHandler {

    private static final Logger logger = Logger.getLogger(this)

    FacebookAuthUtils facebookAuthUtils

    void logout(HttpServletRequest httpServletRequest,
                HttpServletResponse httpServletResponse,
                Authentication authentication) {

        Cookie cookie = facebookAuthUtils.getAuthCookie(httpServletRequest)
        if (cookie != null) {
            logger.info("Cleanup Facebook cookies")
            cookie.maxAge = 0
            cookie.path = '/'
            httpServletResponse.addCookie(cookie)
        }
    }
}
