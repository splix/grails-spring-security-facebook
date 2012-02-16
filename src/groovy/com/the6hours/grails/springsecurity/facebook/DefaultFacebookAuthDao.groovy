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

/**
 * TODO
 *
 * @since 28.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class DefaultFacebookAuthDao implements FacebookAuthDao<Object>, InitializingBean, ApplicationContextAware, GrailsApplicationAware {

    private static def log = Logger.getLogger(this)

    GrailsApplication grailsApplication
    ApplicationContext applicationContext

    String domainClassName

    String connectionPropertyName
    String userDomainClassName
    String rolesPropertyName
    List<String> defaultRoleNames = ['ROLE_USER', 'ROLE_FACEBOOK']

    def facebookAuthService
    DomainsRelation domainsRelation = DomainsRelation.JoinedUser

    Object findUser(long uid) {
        if (facebookAuthService && facebookAuthService.respondsTo('findUser', Long)) {
            return facebookAuthService.findUser(uid)
        }
		Class<?> User = grailsApplication.getDomainClass(domainClassName).clazz
        if (!User) {
            log.error("Can't find domain: $domainClassName")
            return null
        }
        def user = null
        User.withTransaction { status ->
            user = User.findWhere(uid: uid)
            if (domainsRelation == DomainsRelation.JoinedUser) {
                user?.getAt(connectionPropertyName)// load the User object to memory prevent LazyInitializationException
            }
        }
        return user
    }

    Object create(FacebookAuthToken token) {
        if (facebookAuthService && facebookAuthService.respondsTo('create', FacebookAuthToken)) {
            return facebookAuthService.create(token)
        }

        def securityConf = SpringSecurityUtils.securityConfig

        Class<?> UserClass = grailsApplication.getDomainClass(domainClassName)?.clazz
        if (!UserClass) {
            log.error("Can't find domain: $domainClassName")
            return null
        }

        def user = grailsApplication.getDomainClass(domainClassName).newInstance()
        user.uid = token.uid
        if (user.properties.containsKey('accessToken')) {
            user.accessToken = token.accessToken
        }

        def appUser
        if (domainsRelation == DomainsRelation.JoinedUser) {
            if (facebookAuthService && facebookAuthService.respondsTo('createAppUser', UserClass, FacebookAuthToken)) {
                appUser = facebookAuthService.createAppUser(user, token)
            } else {
                Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName).clazz
                if (!UserDomainClass) {
                    log.error("Can't find user domain: $userDomainClassName")
                    return null
                }
                appUser = UserDomainClass.newInstance()
                if (facebookAuthService && facebookAuthService.respondsTo('prepopulateAppUser', UserDomainClass, FacebookAuthToken)) {
                    facebookAuthService.prepopulateAppUser(appUser, token)
                } else {
                    appUser[securityConf.userLookup.usernamePropertyName] = "facebook_$token.uid"
                    appUser[securityConf.userLookup.passwordPropertyName] = token.accessToken
                    appUser[securityConf.userLookup.enabledPropertyName] = true
                    appUser[securityConf.userLookup.accountExpiredPropertyName] = false
                    appUser[securityConf.userLookup.accountLockedPropertyName] = false
                    appUser[securityConf.userLookup.passwordExpiredPropertyName] = false
                }
                UserDomainClass.withTransaction {
                    appUser.save(flush: true, failOnError: true)
                }
            }
            user[connectionPropertyName] = appUser
        }

        if (facebookAuthService && facebookAuthService.respondsTo('onCreate', UserClass, token)) {
            facebookAuthService.onCreate(user, token)
        }

        UserClass.withTransaction {
            user.save(flush: true, failOnError: true)
        }

        if (facebookAuthService && facebookAuthService.respondsTo('afterCreate', UserClass, token)) {
            facebookAuthService.afterCreate(user, token)
        }

        if (facebookAuthService && facebookAuthService.respondsTo('createRoles', UserClass)) {
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
        if (domainsRelation == DomainsRelation.JoinedUser) {
            return user[connectionPropertyName]
        }
        return user
    }

    Collection<GrantedAuthority> getRoles(Object user) {
        if (facebookAuthService && facebookAuthService.respondsTo('getRoles', user.class)) {
            return facebookAuthService.getRoles(user)
        }

        def conf = SpringSecurityUtils.securityConfig
        Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName).clazz
        Collection roles = []
        PersonRole.withTransaction { status ->
            roles = getPrincipal(user)?.getAt(rolesPropertyName)
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

    void afterPropertiesSet() {
        if (!facebookAuthService) {
            if (applicationContext.containsBean('facebookAuthService')) {
                facebookAuthService = applicationContext.getBean('facebookAuthService')
            }
        }
    }
}
