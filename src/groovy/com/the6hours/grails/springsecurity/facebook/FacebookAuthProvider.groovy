package com.the6hours.grails.springsecurity.facebook

import org.apache.commons.lang.StringUtils
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.GrantedAuthority

import org.springframework.security.core.userdetails.User
import org.apache.log4j.Logger
import org.springframework.context.ApplicationContext
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContextAware
import org.springframework.security.core.userdetails.UsernameNotFoundException

public class FacebookAuthProvider implements AuthenticationProvider, InitializingBean, ApplicationContextAware {

    private static def log = Logger.getLogger(this)

    FacebookAuthDao facebookAuthDao
    FacebookAuthUtils facebookAuthUtils
    def facebookAuthService
    ApplicationContext applicationContext

    boolean createNew = true

    public Authentication authenticate(Authentication authentication) {
        FacebookAuthToken token = authentication

        if (token.uid <= 0) {
            if (StringUtils.isEmpty(token.code) && token.accessToken == null) {
                log.error("Token should contain 'code' OR 'accessToken' to get uid")
                token.authenticated = false
                return token
            }
            if (token.code) {
                token.accessToken = facebookAuthUtils.getAccessToken(token.code, token.redirectUri)
                if (token.accessToken == null) {
                    log.error("Can't fetch access_token for code '$token.code'")
                    token.authenticated = false
                    return token
                }
            }
            token.uid = facebookAuthUtils.loadUserUid(token.accessToken.accessToken)
            if (token.uid <= 0) {
                log.error("Can't fetch uid")
                token.authenticated = false
                return token
            }
        }

        def user = facebookAuthDao.findUser(token.uid as Long)
        boolean justCreated = false

        if (user == null) {
            //log.debug "New person $token.uid"
            if (createNew) {
                log.info "Create new facebook user with uid $token.uid"
                if (token.accessToken == null) {
                    token.accessToken = facebookAuthUtils.getAccessToken(token.code, token.redirectUri)
                }
                if (token.accessToken == null) {
                    log.error("Can't create user w/o access_token")
                    throw new CredentialsExpiredException("Can't receive access_token from Facebook")
                }
                user = facebookAuthDao.create(token)
                justCreated = true
            } else {
                log.error "User $token.uid doesn't exist, and creation of a new user is disabled."
                log.debug "To enabled auto creation of users set `grails.plugins.springsecurity.facebook.autoCreate.enabled` to true"
                throw new UsernameNotFoundException("Facebook user with uid $token.uid doesn't exist")
            }
        }
        if (user != null) {
            if (justCreated) {
                log.debug("User is just created")
            }
            if (!justCreated && token.accessToken != null) {
                log.debug("Set new access token for user $user")
                facebookAuthDao.updateToken(user, token)
            }
            if (!facebookAuthDao.hasValidToken(user)) {
                log.debug("User $user has invalid access token")
                String currentAccessToken = facebookAuthDao.getAccessToken(user)
                FacebookAccessToken freshToken = null
                if (currentAccessToken) {
                    try {
                        log.debug("Refresh access token for $user")
                        freshToken = facebookAuthUtils.refreshAccessToken(currentAccessToken)
                        if (!freshToken) {
                            log.warn("Can't refresh access token for user $user")
                        }
                    } catch (IOException e) {
                        log.warn("Can't refresh access token for user $user")
                    }
                }

                if (!freshToken) {
                    log.debug("Load a new access token, from code")
                    freshToken = facebookAuthUtils.getAccessToken(token.code, token.redirectUri)
                }

                if (freshToken) {
                    if (freshToken.accessToken != currentAccessToken) {
                        log.debug("Update access token for user $user")
                        token.accessToken = freshToken
                        facebookAuthDao.updateToken(user, token)
                    } else {
                        log.debug("User $user already have same access token")
                    }
                } else {
                    log.error("Can't update accessToken from Facebook, current token is expired. Disable current authentication")
                    token.authenticated = false
                    return token
                }
            }

            Object appUser = facebookAuthDao.getAppUser(user)
            Object principal = facebookAuthDao.getPrincipal(appUser)

            token.details = null
            token.principal = principal
            if (UserDetails.isAssignableFrom(principal.class)) {
                token.authorities = ((UserDetails)principal).getAuthorities()
            } else {
                token.authorities = facebookAuthDao.getRoles(appUser)
            }

        } else {
            token.authenticated = false
        }
        return token
    }

    public boolean supports(Class<? extends Object> authentication) {
        return FacebookAuthToken.isAssignableFrom(authentication);
    }

    void afterPropertiesSet() {
        if (!facebookAuthService) {
            if (applicationContext.containsBean('facebookAuthService')) {
                log.debug("Use provided facebookAuthService")
                facebookAuthService = applicationContext.getBean('facebookAuthService')
            }
        }
    }
}