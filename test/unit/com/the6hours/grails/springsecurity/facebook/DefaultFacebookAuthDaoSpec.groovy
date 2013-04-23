package com.the6hours.grails.springsecurity.facebook

import spock.lang.Specification

/**
 *
 * Since 20.04.13
 * @author Igor Artamonov, http://igorartamonov.com
 */
class DefaultFacebookAuthDaoSpec extends Specification {

    def "Use service for findUser"() {
        setup:
        def args = []
        TestFacebookUser user = new TestFacebookUser()
        def service = "temp"
        service.metaClass.findUser = { long uid ->
            args << uid
            return user
        }
        DefaultFacebookAuthDao dao = new DefaultFacebookAuthDao()
        dao.facebookAuthService = service
        when:
        def act = dao.findUser(1)
        then:
        act == user
        args == [1]
    }

    def "Find user by uid, when not exist"() {
        setup:
        DefaultFacebookAuthDao dao = new DefaultFacebookAuthDao(
                FacebookUserDomainClazz: TestFacebookUser,
                AppUserDomainClazz: TestAppUser
        )
        List args = []
        TestFacebookUser.metaClass.static.findWhere = { Map x ->
            args << x
            return null
        }
        when:
        def act = dao.findUser(1)
        then:
        act == null
        args[0] == [uid: 1]
    }

    def "Find user by uid, when exist"() {
        setup:
        DefaultFacebookAuthDao dao = new DefaultFacebookAuthDao(
                FacebookUserDomainClazz: TestFacebookUser,
                AppUserDomainClazz: TestAppUser,
                appUserConnectionPropertyName: 'user'
        )
        List args = []
        TestAppUser appUser = new TestAppUser()
        TestFacebookUser user = new TestFacebookUser(uid: 1, user: appUser)
        TestFacebookUser.metaClass.static.findWhere = { Map x ->
            args << x
            return user
        }
        when:
        def act = dao.findUser(1)
        then:
        act == user
        args[0] == [uid: 1]
    }
}
