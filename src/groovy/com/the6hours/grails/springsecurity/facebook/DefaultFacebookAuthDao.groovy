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

        if (domainsRelation == DomainsRelation.JoinedUser) {
            def appUser
            if (facebookAuthService && facebookAuthService.respondsTo('createAppUser')) {
                appUser = facebookAuthService.createAppUser()
            } else {
                Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName).clazz
                if (!UserDomainClass) {
                    log.error("Can't find user domain: $userDomainClassName")
                    return null
                }
                appUser = UserDomainClass.newInstance()
                if (facebookAuthService && facebookAuthService.respondsTo('prepopulateAppUser', UserDomainClass)) {
                    facebookAuthService.prepopulateAppUser(appUser)
                } else {
                    appUser.username = "facebook_$token.uid"
                    appUser.password = token.accessToken
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
        if (roles.first().class == String) {
            return roles.collect {
                new GrantedAuthorityImpl(it)
            }
        } else {
            return roles.collect {
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
