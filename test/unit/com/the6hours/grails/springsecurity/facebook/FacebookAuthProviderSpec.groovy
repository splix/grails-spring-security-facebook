package com.the6hours.grails.springsecurity.facebook

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
}
