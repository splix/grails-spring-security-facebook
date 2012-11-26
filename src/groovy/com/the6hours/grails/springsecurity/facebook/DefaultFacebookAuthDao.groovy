package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationContext
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.support.aware.GrailsApplicationAware
import org.apache.log4j.Logger
import org.springframework.security.core.userdetails.UserDetails
import java.util.concurrent.TimeUnit

import org.codehaus.groovy.grails.plugins.springsecurity.GormUserDetailsService

/**
 * TODO
 *
 * @since 28.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class DefaultFacebookAuthDao implements FacebookAuthDao<Object, Object>, InitializingBean, ApplicationContextAware, GrailsApplicationAware {

    private static def log = Logger.getLogger(this)

    GrailsApplication grailsApplication
    ApplicationContext applicationContext
    def coreUserDetailsService

    String domainClassName

    String appUserConnectionPropertyName

    String userDomainClassName
    String rolesPropertyName
    List<String> defaultRoleNames = ['ROLE_USER', 'ROLE_FACEBOOK']

    def facebookAuthService
    DomainsRelation domainsRelation = DomainsRelation.JoinedUser

    private Class<?> FacebookUserDomainClazz
    private Class<?> AppUserDomainClazz

    Object getFacebookUser(Object user) {
        if (facebookAuthService && facebookAuthService.respondsTo('getFacebookUser', user.class)) {
            return facebookAuthService.getFacebookUser(user)
        }
        if (domainsRelation == DomainsRelation.JoinedUser) {
            def loaded = null
            FacebookUserDomainClazz.withTransaction { status ->
                user = FacebookUserDomainClazz.findWhere("$appUserConnectionPropertyName": user)
            }
            return loaded
        }
        if (domainsRelation == DomainsRelation.SameObject) {
            return user
        }
        log.error("Invalid domainsRelation value: $domainsRelation")
        return user
    }

    Object getAppUser(Object facebookUser) {
        if (facebookAuthService && facebookAuthService.respondsTo('getAppUser', facebookUser.class)) {
            return facebookAuthService.getAppUser(facebookUser)
        }
        if (facebookUser == null) {
            log.warn("Passed facebookUser is null")
            return facebookUser
        }
        if (domainsRelation == DomainsRelation.SameObject) {
            return facebookUser
        }
        if (domainsRelation == DomainsRelation.JoinedUser) {
            Object result = null
            FacebookUserDomainClazz.withTransaction { status ->
                facebookUser.merge()
                result = facebookUser.getAt(appUserConnectionPropertyName)
            }
            return result
        }
        log.error("Invalid domainsRelation value: $domainsRelation")
        return facebookUser
    }

    Object findUser(long uid) {
        if (facebookAuthService && facebookAuthService.respondsTo('findUser', Long)) {
            return facebookAuthService.findUser(uid)
        }
        def user = null
        FacebookUserDomainClazz.withTransaction { status ->
            user = FacebookUserDomainClazz.findWhere(uid: uid)
            if (user
                    && !(facebookAuthService && facebookAuthService.respondsTo('getFacebookUser', user.class))
                    && domainsRelation == DomainsRelation.JoinedUser) {
                getFacebookUser(user) // load the User object to memory prevent LazyInitializationException
            }
        }
        return user
    }

    Object create(FacebookAuthToken token) {
        if (facebookAuthService && facebookAuthService.respondsTo('create', FacebookAuthToken)) {
            return facebookAuthService.create(token)
        }

        def securityConf = SpringSecurityUtils.securityConfig

        def user = grailsApplication.getDomainClass(domainClassName).newInstance()
        user.uid = token.uid
        if (user.properties.containsKey('accessToken')) {
            user.accessToken = token.accessToken?.accessToken
        }
        if (user.properties.containsKey('accessTokenExpires')) {
            user.accessTokenExpires = token.accessToken?.expireAt
        }

        def appUser
        if (domainsRelation == DomainsRelation.JoinedUser) {
            if (facebookAuthService && facebookAuthService.respondsTo('createAppUser', FacebookUserDomainClazz, FacebookAuthToken)) {
                appUser = facebookAuthService.createAppUser(user, token)
            } else {
                appUser = AppUserDomainClazz.newInstance()
                if (facebookAuthService && facebookAuthService.respondsTo('prepopulateAppUser', AppUserDomainClazz, FacebookAuthToken)) {
                    facebookAuthService.prepopulateAppUser(appUser, token)
                } else {
                    appUser[securityConf.userLookup.usernamePropertyName] = "facebook_$token.uid"
                    appUser[securityConf.userLookup.passwordPropertyName] = token.accessToken.accessToken
                    appUser[securityConf.userLookup.enabledPropertyName] = true
                    appUser[securityConf.userLookup.accountExpiredPropertyName] = false
                    appUser[securityConf.userLookup.accountLockedPropertyName] = false
                    appUser[securityConf.userLookup.passwordExpiredPropertyName] = false
                }
                AppUserDomainClazz.withTransaction {
                    appUser.save(flush: true, failOnError: true)
                }
            }
            user[appUserConnectionPropertyName] = appUser
        }

        if (facebookAuthService && facebookAuthService.respondsTo('onCreate', FacebookUserDomainClazz, token)) {
            facebookAuthService.onCreate(user, token)
        }

        FacebookUserDomainClazz.withTransaction {
            user.save(flush: true, failOnError: true)
        }

        if (facebookAuthService && facebookAuthService.respondsTo('afterCreate', FacebookUserDomainClazz, token)) {
            facebookAuthService.afterCreate(user, token)
        }

        if (facebookAuthService && facebookAuthService.respondsTo('createRoles', FacebookUserDomainClazz)) {
            facebookAuthService.createRoles(user)
        } else {
            Class<?> PersonRole = grailsApplication.getDomainClass(securityConf.userLookup.authorityJoinClassName).clazz
            Class<?> Authority = grailsApplication.getDomainClass(securityConf.authority.className).clazz
            PersonRole.withTransaction { status ->
                defaultRoleNames.each { String roleName ->
                    String findByField = securityConf.authority.nameField[0].toUpperCase() + securityConf.authority.nameField.substring(1)
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

    Object getPrincipal(Object user) {
        if (facebookAuthService && facebookAuthService.respondsTo('getPrincipal', user.class)) {
            return facebookAuthService.getPrincipal(user)
        }
        if (coreUserDetailsService) {
            return coreUserDetailsService.createUserDetails(user, getRoles(user))
        }
        return user
    }

    Collection<GrantedAuthority> getRoles(Object user) {
        if (facebookAuthService && facebookAuthService.respondsTo('getRoles', user.class)) {
            return facebookAuthService.getRoles(user)
        }

        if (UserDetails.isAssignableFrom(user.class)) {
            return ((UserDetails)user).getAuthorities()
        }

        def conf = SpringSecurityUtils.securityConfig
        Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)?.clazz
        if (!PersonRole) {
            log.error("Can't load roles for user $user. Reason: can't find ${conf.userLookup.authorityJoinClassName} class")
            return []
        }
        Collection roles = []
        PersonRole.withTransaction { status ->
            roles = user?.getAt(rolesPropertyName)
        }
        if (!roles) {
            roles = []
        }
        if (roles.empty) {
            return roles
        }
        return roles.collect {
            if (it instanceof String) {
                return new GrantedAuthorityImpl(it.toString())
            } else {
                new GrantedAuthorityImpl(it[conf.authority.nameField])
            }
        }
    }

    Boolean hasValidToken(Object facebookUser) {
        if (facebookAuthService && facebookAuthService.respondsTo('hasValidToken', facebookUser.class)) {
            return facebookAuthService.hasValidToken(facebookUser)
        }
        if (facebookUser.properties.containsKey('accessToken')) {
            if (facebookUser.accessToken == null) {
                return false
            }
        }
        if (facebookUser.properties.containsKey('accessTokenExpires')) {
            if (facebookUser.accessTokenExpires == null) {
                return false
            }
            Date goodExpiration = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(4))
            if (goodExpiration.after(facebookUser.accessTokenExpires)) {
                return false
            }
        } else {
            log.warn("Domain ${facebookUser.class} don't have 'acccessTokenExpires' field, can't check accessToken expiration")
        }
        return true //not supported currently
    }

    void updateToken(Object facebookUser, FacebookAuthToken token) {
        if (facebookAuthService && facebookAuthService.respondsTo('updateToken', facebookUser.class, token.class)) {
            facebookAuthService.updateToken(facebookUser, token)
            return
        }
        log.debug("Update access token to $token")
        if (facebookUser.properties.containsKey('accessToken')) {
            facebookUser.accessToken = token.accessToken.accessToken
        }
        if (facebookUser.properties.containsKey('accessTokenExpires')) {
            facebookUser.accessTokenExpires = token.accessToken.expireAt
        }
        FacebookUserDomainClazz.withTransaction {
            facebookUser.save()
        }
    }

    String getAccessToken(Object facebookUser) {
        if (facebookAuthService && facebookAuthService.respondsTo('getAccessToken', facebookUser.class)) {
            return facebookAuthService.getAccessToken(facebookUser)
        }
        if (facebookUser.properties.containsKey('accessToken')) {
            return facebookUser.accessToken
        }
        return null
    }

    void afterPropertiesSet() {
        if (!facebookAuthService) {
            if (applicationContext.containsBean('facebookAuthService')) {
                log.debug("Use provided facebookAuthService")
                facebookAuthService = applicationContext.getBean('facebookAuthService')
            }
        }

        //validate configuration

        List serviceMethods = []
        if (facebookAuthService) {
            facebookAuthService.metaClass.methods.each {
                serviceMethods<< it.name
            }
        }

        def conf = SpringSecurityUtils.securityConfig
        if (!serviceMethods.contains('getRoles')) {
            Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
            if (UserDomainClass == null || !UserDetails.isAssignableFrom(UserDomainClass)) {
                if (!conf.userLookup.authorityJoinClassName) {
                    log.error("Don't have authority join class configuration. Please configure 'grails.plugins.springsecurity.userLookup.authorityJoinClassName' value")
                } else if (!grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)) {
                    log.error("Can't find authority join class (${conf.userLookup.authorityJoinClassName}). Please configure 'grails.plugins.springsecurity.userLookup.authorityJoinClassName' value, or create your own 'List<GrantedAuthority> facebookAuthService.getRoles(user)'")
                }
            }
        }
        if (!serviceMethods.contains('findUser')) {
            if (!domainClassName) {
                log.error("Don't have facebook user class configuration. Please configure 'grails.plugins.springsecurity.facebook.domain.classname' value")
            } else {
                Class<?> User = grailsApplication.getDomainClass(domainClassName)?.clazz
                if (!User) {
                    log.error("Can't find facebook user class ($domainClassName). Please configure 'grails.plugins.springsecurity.facebook.domain.classname' value, or create your own 'Object facebookAuthService.findUser(long)'")
                }
            }
        }

        if (coreUserDetailsService != null) {
            if (!(coreUserDetailsService instanceof GormUserDetailsService && coreUserDetailsService.respondsTo('createUserDetails'))) {
                log.warn("UserDetailsService from spring-security-core don't have method 'createUserDetails()'")
                coreUserDetailsService = null
            }
        } else {
            log.warn("No UserDetailsService bean from spring-security-core")
        }

        FacebookUserDomainClazz = grailsApplication.getDomainClass(domainClassName)?.clazz
        if (!FacebookUserDomainClazz) {
            log.error("Can't find domain: $domainClassName")
        }
        AppUserDomainClazz = grailsApplication.getDomainClass(userDomainClassName)?.clazz
        if (!AppUserDomainClazz) {
            log.error("Can't find domain: $userDomainClassName")
        }

    }
}
