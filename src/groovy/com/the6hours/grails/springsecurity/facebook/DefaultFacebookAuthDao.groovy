package com.the6hours.grails.springsecurity.facebook

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.userdetails.GormUserDetailsService

import java.util.concurrent.TimeUnit

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.support.aware.GrailsApplicationAware
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.dao.OptimisticLockingFailureException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

/**
 * Default Facebook Authentication Dao
 * Covers most cases, and custom logic could be added with custom FacebookAuthService
 *
 * @since 28.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class DefaultFacebookAuthDao implements FacebookAuthDao<Object, Object>, InitializingBean, ApplicationContextAware, GrailsApplicationAware {

    private static final Logger log = LoggerFactory.getLogger(this)

    List<String> defaultRoleNames = ['ROLE_USER', 'ROLE_FACEBOOK']

    GrailsApplication grailsApplication
    ApplicationContext applicationContext
    def coreUserDetailsService
    def facebookAuthService

    String appUserConnectionPropertyName = 'user'
    String rolesPropertyName

    @Deprecated String domainClassName
    @Deprecated String userDomainClassName
    @Deprecated DomainsRelation domainsRelation

    private Class<?> FacebookUserDomainClazz
    private Class<?> AppUserDomainClazz

    boolean isSameDomain() {
        FacebookUserDomainClazz == AppUserDomainClazz
    }

    def getFacebookUser(appUser) {
        if (appUser && facebookAuthService?.respondsTo('getFacebookUser', appUser.class)) {
            return facebookAuthService.getFacebookUser(appUser)
        }
        if (isSameDomain()) {
            return appUser
        }
        FacebookUserDomainClazz.withTransaction { status ->
            FacebookUserDomainClazz.findWhere((appUserConnectionPropertyName): appUser)
        }
    }

    def getAppUser(facebookUser) {
        if (!facebookUser) {
            log.warn("Passed facebookUser is null")
            return facebookUser
        }

        if (facebookAuthService?.respondsTo('getAppUser', facebookUser.class)) {
            return facebookAuthService.getAppUser(facebookUser)
        }

        if (isSameDomain()) {
            return facebookUser
        }

        FacebookUserDomainClazz.withTransaction { status ->
            facebookUser.merge()
            facebookUser.getProperty(appUserConnectionPropertyName)
        }
    }

    def findUser(long uid) {
        if (facebookAuthService?.respondsTo('findUser', Long)) {
            return facebookAuthService.findUser(uid)
        }

        def user
        FacebookUserDomainClazz.withTransaction { status ->
            user = FacebookUserDomainClazz.findWhere(uid: uid)
            if (!user) {
                return user
            }

            if (!isSameDomain()) {
                if (appUserConnectionPropertyName) {
                    // load the User object to memory prevent LazyInitializationException
                    def appUser = user.getProperty(appUserConnectionPropertyName)
                    if (!appUser) {
                        log.warn("No appUser for facebookUser ${user}. Property ${appUserConnectionPropertyName} have null value")
                    }
                } else {
                    log.error("appUserConnectionPropertyName is not configured")
                }
            }
        }
        return user
    }

    def create(FacebookAuthToken token) {
        if (facebookAuthService?.respondsTo('create', FacebookAuthToken)) {
            return facebookAuthService.create(token)
        }

        def securityConf = SpringSecurityUtils.securityConfig

        def user = grailsApplication.getDomainClass(FacebookUserDomainClazz.canonicalName).newInstance()
        user.setProperty('uid', token.uid)
        if (user.hasProperty('accessToken')) {
            user.setProperty('accessToken', token.accessToken?.accessToken)
        }
        if (user.hasProperty('accessTokenExpires')) {
            user.setProperty('accessTokenExpires', token.accessToken?.expireAt)
        }

        def appUser
        if (!isSameDomain()) {
            if (facebookAuthService?.respondsTo('createAppUser', FacebookUserDomainClazz, FacebookAuthToken)) {
                appUser = facebookAuthService.createAppUser(user, token)
            } else {
                appUser = grailsApplication.getDomainClass(AppUserDomainClazz.canonicalName).newInstance()
                if (facebookAuthService?.respondsTo('prepopulateAppUser', AppUserDomainClazz, FacebookAuthToken)) {
                    facebookAuthService.prepopulateAppUser(appUser, token)
                } else {
                    def ul = securityConf.userLookup
                    appUser.setProperty(ul.usernamePropertyName, "facebook_$token.uid")
                    appUser.setProperty(ul.passwordPropertyName, token.accessToken?.accessToken)
                    appUser.setProperty(ul.enabledPropertyName, true)
                    appUser.setProperty(ul.accountExpiredPropertyName, false)
                    appUser.setProperty(ul.accountLockedPropertyName, false)
                    appUser.setProperty(ul.passwordExpiredPropertyName, false)
                }
                AppUserDomainClazz.withTransaction {
                    appUser.save(failOnError: true)
                }
            }
            user[appUserConnectionPropertyName] = appUser
        } else {
            appUser = user
        }

        if (facebookAuthService?.respondsTo('onCreate', FacebookUserDomainClazz, FacebookAuthToken)) {
            facebookAuthService.onCreate(user, token)
        }

        FacebookUserDomainClazz.withTransaction {
            user.save(failOnError: true)
        }

        if (facebookAuthService?.respondsTo('afterCreate', FacebookUserDomainClazz, FacebookAuthToken)) {
            facebookAuthService.afterCreate(user, token)
        }

        if (facebookAuthService?.respondsTo('createRoles', FacebookUserDomainClazz)) {
            facebookAuthService.createRoles(user)
        } else {
            Class<?> PersonRole = grailsApplication.getDomainClass(securityConf.userLookup.authorityJoinClassName)?.clazz
            Class<?> Authority = grailsApplication.getDomainClass(securityConf.authority.className)?.clazz
            String authorityNameField = securityConf.authority.nameField
            String findByField = authorityNameField[0].toUpperCase() + authorityNameField.substring(1)
            PersonRole.withTransaction { status ->
                defaultRoleNames.each { String roleName ->
                    def auth = Authority."findBy${findByField}"(roleName)
                    if (auth) {
                        PersonRole.create(appUser, auth)
                    } else {
                        log.error("Can't find authority for name '$roleName'")
                    }
                }
            }
        }

        return user
    }

    def getPrincipal(user) {
        if (user && facebookAuthService?.respondsTo('getPrincipal', user.class)) {
            return facebookAuthService.getPrincipal(user)
        }
        if (coreUserDetailsService) {
            return coreUserDetailsService.createUserDetails(user, getRoles(user))
        }
        return user
    }

    Collection<GrantedAuthority> getRoles(user) {
        if (!user) {
            return []
        }

        if (facebookAuthService?.respondsTo('getRoles', user.class)) {
            return facebookAuthService.getRoles(user)
        }

        if (user instanceof UserDetails) {
            return user.authorities
        }

        def conf = SpringSecurityUtils.securityConfig
        Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)?.clazz
        if (!PersonRole) {
            log.error("Can't load roles for user $user. Reason: can't find ${conf.userLookup.authorityJoinClassName} class")
            return []
        }

        Collection roles
        PersonRole.withTransaction { status ->
            roles = user?.getProperty(rolesPropertyName)
        }
        if (!roles) {
            roles = []
        }
        if (roles.empty) {
            return roles
        }

        String nameField = conf.authority.nameField
        return roles.collect {
            new SimpleGrantedAuthority(it instanceof CharSequence ? it.toString() : it.getProperty(nameField))
        }
    }

    Boolean hasValidToken(facebookUser) {
        if (facebookUser && facebookAuthService?.respondsTo('hasValidToken', facebookUser.class)) {
            return facebookAuthService.hasValidToken(facebookUser)
        }
        if (facebookUser.hasProperty('accessToken')) {
            if (!facebookUser.getProperty('accessToken')) {
                return false
            }
        }
        if (facebookUser.hasProperty('accessTokenExpires')) {
            if (!facebookUser.getProperty('accessTokenExpires')) {
                return false
            }
            Date goodExpiration = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15))
            Date currentExpires = facebookUser.getProperty('accessTokenExpires')
            if (currentExpires.before(goodExpiration)) {
                return false
            }
        } else {
            log.warn("Domain ${facebookUser.class} don't have 'acccessTokenExpires' field, can't check accessToken expiration. And it's very likely that your database contains expired tokens")
        }
        return true
    }

    void updateToken(facebookUser, FacebookAuthToken token) {
        if (facebookUser && facebookAuthService?.respondsTo('updateToken', facebookUser.class, FacebookAuthToken)) {
            facebookAuthService.updateToken(facebookUser, token)
            return
        }
        if (!token.accessToken) {
            log.error("No access token $token")
            return
        }
        if (!token.accessToken.accessToken) {
            log.warn("Update to empty accessToken for user $facebookUser")
        }
        log.debug("Update access token to $token.accessToken for $facebookUser")
        FacebookUserDomainClazz.withTransaction {
            try {
                boolean updated = false
                if (!facebookUser.isAttached()) {
                    facebookUser.attach()
                }
                if (facebookUser.hasProperty('accessToken')) {
                    if (facebookUser.getProperty('accessToken') != token.accessToken.accessToken) {
                        updated = true
                        facebookUser.setProperty('accessToken', token.accessToken.accessToken)
                    }
                }
                if (updated && facebookUser.hasProperty('accessTokenExpires')) {
                    if (!equalDates(facebookUser.getProperty('accessTokenExpires'), token.accessToken.expireAt)) {
                        if (token.accessToken.expireAt || !token.accessToken.accessToken) { //allow null only if both expireAt and accessToken are null
                            updated = true
                            facebookUser.setProperty('accessTokenExpires', token.accessToken.expireAt)
                        } else {
                            log.warn("Provided accessToken.expiresAt value is null. Skip update")
                        }
                    } else {
                        log.warn("A new accessToken have same token but different expires: $token")
                    }
                }
                if (updated) {
                    facebookUser.save()
                }
            } catch (OptimisticLockingFailureException e) {
                log.warn("Seems that token was updated in another thread (${e.message}). Skip")
            } catch (Throwable e) {
                log.error("Can't update token", e)
            }
        }
    }

    boolean equalDates(x, y) {
        long xtime = dateToLong(x)
        long ytime = dateToLong(y)
        return xtime >= 0 && ytime >= 0 && Math.abs(xtime - ytime) < 1000 //for dates w/o millisecond
    }

    long dateToLong(date) {
        if (date == null) {
            return -1
        }
        if (date instanceof Date) { //java.sql.Timestamp extends Date
            return date.time
        }
        if (date instanceof Number) {
            return date.toLong()
        }
        log.warn("Cannot convert date: $date (class: ${date.class.name})")
        return -1
    }

    String getAccessToken(facebookUser) {
        if (facebookUser && facebookAuthService?.respondsTo('getAccessToken', facebookUser.class)) {
            return facebookAuthService.getAccessToken(facebookUser)
        }
        if (facebookUser.hasProperty('accessToken')) {
            if (facebookUser.hasProperty('accessTokenExpires')) {
                Date currentExpires = facebookUser.getProperty('accessTokenExpires')
                if (currentExpires == null) {
                    log.debug("Current access token don't have expiration timeout, and should be updated")
                    return null
                }
                if (currentExpires.before(new Date())) {
                    log.debug("Current access token is expired, and cannot be used anymore")
                    return null
                }
            }
            return facebookUser.getProperty('accessToken')
        }
        return null
    }

    void afterPropertiesSet() {
        if (!facebookAuthService) {
            if (applicationContext.containsBean('facebookAuthService')) {
                log.debug("Use provided facebookAuthService")
                facebookAuthService = applicationContext.facebookAuthService
            }
        }

        //validate configuration

        List serviceMethods = facebookAuthService ? facebookAuthService.metaClass.methods*.name : []

        def conf = SpringSecurityUtils.securityConfig
        if (!serviceMethods.contains('getRoles')) {
            if (!userDomainClassName) {
                log.error("User domain class name is not configured")
            } else {
                Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
                if (!UserDomainClass || !UserDetails.isAssignableFrom(UserDomainClass)) {
                    if (!conf.userLookup.authorityJoinClassName) {
                        log.error("Don't have authority join class configuration. Please configure 'grails.plugin.springsecurity.userLookup.authorityJoinClassName' value")
                    } else if (!grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)) {
                        log.error("Can't find authority join class (${conf.userLookup.authorityJoinClassName}). Please configure 'grails.plugin.springsecurity.userLookup.authorityJoinClassName' value, or create your own 'List<GrantedAuthority> facebookAuthService.getRoles(user)'")
                    }
                }
            }
        }
        if (!serviceMethods.contains('findUser')) {
            if (!domainClassName) {
                log.error("Don't have facebook user class configuration. Please configure 'grails.plugin.springsecurity.facebook.domain.classname' value")
            } else {
                Class<?> User = grailsApplication.getDomainClass(domainClassName)?.clazz
                if (!User) {
                    log.error("Can't find facebook user class ($domainClassName). Please configure 'grails.plugin.springsecurity.facebook.domain.classname' value, or create your own 'Object facebookAuthService.findUser(long)'")
                }
            }
        }

        if (coreUserDetailsService) {
            if (!(coreUserDetailsService.respondsTo('createUserDetails'))) {
                log.error("UserDetailsService from spring-security-core don't have method 'createUserDetails()'")
                coreUserDetailsService = null
            } else if (!(coreUserDetailsService instanceof GormUserDetailsService)) {
                log.warn("UserDetailsService from spring-security-core isn't instance of GormUserDetailsService, but: ${coreUserDetailsService.class}")
            }
        } else {
            log.warn("No UserDetailsService bean from spring-security-core")
        }

        if (domainClassName && !FacebookUserDomainClazz) {
            FacebookUserDomainClazz = grailsApplication.getDomainClass(domainClassName)?.clazz
        }
        if (!FacebookUserDomainClazz) {
            log.error("Can't find domain: $domainClassName")
        }
        if (userDomainClassName && !AppUserDomainClazz) {
            AppUserDomainClazz = grailsApplication.getDomainClass(userDomainClassName)?.clazz
        }
        if (!AppUserDomainClazz) {
            log.error("Can't find domain: $userDomainClassName")
        }
        if (FacebookUserDomainClazz && AppUserDomainClazz) {
            if (FacebookUserDomainClazz == AppUserDomainClazz) {
                domainsRelation = DomainsRelation.SameObject
            }
        }
        if (domainsRelation == null) {
            domainsRelation = DomainsRelation.JoinedUser
        }
    }
}
