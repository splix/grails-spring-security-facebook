package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.web.authentication.logout.LogoutHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import javax.servlet.http.Cookie
import org.apache.log4j.Logger
import java.util.regex.Matcher
import grails.plugin.springsecurity.SpringSecurityUtils

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 04.11.11
 */
class FacebookAuthCookieLogoutHandler implements LogoutHandler {

    private static final Logger logger = Logger.getLogger(this)

    FacebookAuthUtils facebookAuthUtils

    boolean cleanupToken = true
    FacebookAuthDao facebookAuthDao

    void logout(HttpServletRequest httpServletRequest,
                HttpServletResponse httpServletResponse,
                Authentication authentication) {

      String baseDomain = null

      List<Cookie> cookies = httpServletRequest.cookies.findAll { Cookie it ->
          //FacebookAuthUtils.log.debug("Cookier $it.name, expected $cookieName")
          return it.name ==~ /fb\w*_$facebookAuthUtils.applicationId/
      }

      baseDomain = cookies.find {
        return it.name == "fbm_\$facebookAuthUtils.applicationId" && it.value ==~ /base_domain=.+/
      }?.value?.split('=')?.last()

      if (!baseDomain) {
        //Facebook uses invalid cookie format, so sometimes we need to parse it manually
        String rawCookie = httpServletRequest.getHeader('Cookie')
        logger.info("raw cookie: $rawCookie")
        if (rawCookie) {
          Matcher m = rawCookie =~ /fbm_$facebookAuthUtils.applicationId=base_domain=(.+?);/
          if (m.find()) {
            baseDomain = m.group(1)
          }
        }
      }

      if (!baseDomain) {
          def conf = SpringSecurityUtils.securityConfig.facebook
          if (conf.host && conf.host.length() > 0) {
              baseDomain = conf.host
          }
          logger.debug("Can't find base domain for Facebook cookie. Use '$baseDomain'")
      }

      cookies.each { cookie ->
        cookie.maxAge = 0
        cookie.path = '/'
        if (baseDomain) {
          cookie.domain = baseDomain
        }
        httpServletResponse.addCookie(cookie)
      }

      if (cleanupToken && (authentication instanceof FacebookAuthToken)) {
          cleanupToken(authentication)
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
        } catch (Throwable t) {
            logger.error("Can't remove existing token", t)
        }
    }
}
