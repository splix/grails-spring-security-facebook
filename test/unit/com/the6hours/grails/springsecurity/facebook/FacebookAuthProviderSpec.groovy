package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.userdetails.UsernameNotFoundException
import spock.lang.Specification

/**
 *
 * Created at 20.04.13
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class FacebookAuthProviderSpec extends Specification {

    def "Return existing user on second sign-in"() {
        setup:
        FacebookAuthDao dao = Mock(FacebookAuthDao)
        FacebookAuthUtils utils = Mock(FacebookAuthUtils)
        FacebookAuthProvider provider = new FacebookAuthProvider(
                facebookAuthDao: dao,
                facebookAuthUtils: utils
        )
        FacebookAuthToken token = new FacebookAuthToken(
                uid: 1
        )
        TestFacebookUser user = new TestFacebookUser(
                uid: 1
        )
        TestAppUser appUser = new TestAppUser()
        when:
        provider.authenticate(token)
        then:
        1 * dao.findUser(1) >> user
        1 * dao.getAppUser(user) >> appUser
        1 * dao.getPrincipal(appUser) >> "hello!"
        1 * dao.getRoles(_) >> []
        1 * utils.getAccessToken(_, _) >> new FacebookAccessToken(
                accessToken: 'test',
                expireAt: new Date()
        )
    }

    def "Create a new user"() {
        setup:
        FacebookAuthDao dao = Mock(FacebookAuthDao)
        FacebookAuthUtils utils = Mock(FacebookAuthUtils)
        FacebookAuthProvider provider = new FacebookAuthProvider(
                facebookAuthDao: dao,
                facebookAuthUtils: utils
        )
        FacebookAuthToken token = new FacebookAuthToken(
                uid: 1
        )
        TestFacebookUser user = new TestFacebookUser(
                uid: 1
        )
        TestAppUser appUser = new TestAppUser()
        FacebookAccessToken accessToken = new FacebookAccessToken(
                accessToken: 'test',
                expireAt: new Date()
        )
        when:
        provider.authenticate(token)
        then:
        1 * dao.findUser(1) >> null
        1 * utils.getAccessToken(_, _) >> accessToken //load token before creation
        1 * dao.create(token) >> user //create user
        1 * dao.hasValidToken(user) >> true
        1 * dao.getAppUser(user) >> appUser
        1 * dao.getPrincipal(appUser) >> "hello!"
        1 * dao.getRoles(_) >> []
    }

    def "Don't create a new user when disabled"() {
        setup:
        FacebookAuthDao dao = Mock(FacebookAuthDao)
        FacebookAuthUtils utils = Mock(FacebookAuthUtils)
        FacebookAuthProvider provider = new FacebookAuthProvider(
                facebookAuthDao: dao,
                facebookAuthUtils: utils,
                createNew: false
        )
        FacebookAuthToken token = new FacebookAuthToken(
                uid: 1
        )
        when:
        provider.authenticate(token)
        then:
        1 * dao.findUser(1) >> null
        thrown(UsernameNotFoundException)
    }

}
