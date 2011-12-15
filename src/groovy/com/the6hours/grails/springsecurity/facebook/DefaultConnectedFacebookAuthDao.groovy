package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.GrantedAuthority

/**
 * TODO
 *
 * @since 28.10.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class DefaultConnectedFacebookAuthDao implements FacebookAuthDao {

    def grailsApplication

    String domainClassName

    String connectionPropertyName
    String userDomainClassName
    String rolesPropertyName

    FacebookUserDomain findUser(long uid) {
		Class<?> User = grailsApplication.getDomainClass(domainClassName).clazz
        def user = null
        User.withTransaction { status ->
            user = User.findWhere(uid: uid)
            user?.user // load the User object to memory prevent LazyInitializationException
        }
        return user
    }

    FacebookUserDomain create(FacebookAuthToken token) {
        Class<FacebookUserDomain> userClass = grailsApplication.getDomainClass(domainClassName).clazz
        FacebookUserDomain user = userClass.newInstance()
        user.secret = token.secret
        user.session = token.session
        user.uid = token.uid
        user[connectionPropertyName] = createAppUser(token)
        update(user)

        return user
    }

    void update(FacebookUserDomain user) {

    }

    Object getPrincipal(FacebookUserDomain user) {
        return null
    }

    Collection<GrantedAuthority> getRoles(FacebookUserDomain user) {
        return null
    }
}
