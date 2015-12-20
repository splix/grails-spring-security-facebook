package com.the6hours.grails.springsecurity.facebook

import grails.plugin.springsecurity.SpringSecurityUtils
import groovy.transform.CompileStatic

import java.util.regex.Matcher

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutHandler

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 04.11.11
 */
@CompileStatic
class FacebookAuthCookieLogoutHandler implements LogoutHandler {

    private static final Logger logger = LoggerFactory.getLogger(this)

    FacebookAuthDao facebookAuthDao
    FacebookAuthUtils facebookAuthUtils
    boolean cleanupToken = true

    void logout(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
        String baseDomain = null
        String expectedCookieName = ['fbsr', facebookAuthUtils.applicationId].join('_')

        Collection<Cookie> cookies = request.cookies?.findAll { Cookie c ->
            c.name == expectedCookieName
        }

        if (!cookies) {
            logger.debug("No FB cookies")
            return
        }

        baseDomain = cookies.find { Cookie c ->
            c.name == expectedCookieName && c.value ==~ /base_domain=.+/
        }?.value?.split('=')?.last()

        if (!baseDomain) {
            //Facebook uses invalid cookie format, so sometimes we need to parse it manually
            String rawCookie = request.getHeader('Cookie')
            logger.debug("raw cookie: $rawCookie")
            if (rawCookie) {
                Matcher m = rawCookie =~ /$expectedCookieName=base_domain=(.+?);/
                if (m.find()) {
                    baseDomain = m.group(1)
                }
            }
        }

        if (!baseDomain) {
            ConfigObject conf = (ConfigObject)SpringSecurityUtils.securityConfig.facebook
            if (conf.containsKey('host')) {
                baseDomain = conf.host
            } else {
                logger.warn("Can't find base domain for Facebook cookie. Please configure app host name as grails.plugin.springsecurity.facebook.host")
                return
            }
        }

        cookies.each { Cookie cookie ->
            cookie.maxAge = 0
            cookie.path = '/'
            if (baseDomain) {
                cookie.domain = baseDomain
            }
            response.addCookie cookie
        }

        if (cleanupToken && (auth instanceof FacebookAuthToken)) {
            cleanupToken(auth)
        }
    }

    void cleanupToken(FacebookAuthToken authentication) {
        if (!facebookAuthDao) {
            logger.error("No FacebookAuthDao")
            return
        }
        try {
            def user = facebookAuthDao.findUser(authentication.uid)
            authentication.accessToken = null
            facebookAuthDao.updateToken(user, authentication)
        }
        catch (Throwable t) {
            logger.error("Can't remove existing token", t)
        }
    }
}
