package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.GrantedAuthority
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 20.12.11
 */
class DefaultIncludedFacebookAuthDao implements FacebookAuthDao {

    String uidPropertyName
    String rolesPropertyName
    String accessTokenPropertyName
    String userDomainClassName
    List<String> defaultRoles

    GrailsApplication grailsApplication

    Object findUser(long uid) {
        Class userClass = grailsApplication.getDomainClass(userDomainClassName).clazz
        userClass."findBy$uidPropertyName"(uid)
    }

    Object create(FacebookAuthToken token) {
        Class User = grailsApplication.getDomainClass(userDomainClassName).clazz
        def user = User.newInstance()
        user.properties[uidPropertyName] = token.uid
        user.properties[accessTokenPropertyName] = token.accessToken

        def conf = SpringSecurityUtils.securityConfig
        defaultRoles.collect {
            Class<?> Role = grailsApplication.getDomainClass(conf.authority.className).clazz
            def role = Role.findByAuthority(it)
            if (!role) {
                role = Role.newInstance()
                role.properties[conf.authority.nameField] = it
                Role.withTransaction { status ->
                    role.save()
                }
            }
            return role
        }.each { role ->
            Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName).clazz
            PersonRole.withTransaction { status ->
                PersonRole.create(user, role, false)
            }
        }
        return user
    }

    void update(Object user) {
        Class User = grailsApplication.getDomainClass(userDomainClassName).clazz
        User.withTransaction {
            user.save()
        }
    }

    Object getPrincipal(Object user) {
        return user
    }

    Collection<GrantedAuthority> getRoles(Object user) {
        return user?.getAt(rolesPropertyName)
    }
}
