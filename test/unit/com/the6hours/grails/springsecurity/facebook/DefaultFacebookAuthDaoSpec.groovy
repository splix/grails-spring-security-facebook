package com.the6hours.grails.springsecurity.facebook

import org.codehaus.groovy.grails.commons.DefaultGrailsApplication
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import spock.lang.Specification

/**
 *
 * Since 20.04.13
 * @author Igor Artamonov, http://igorartamonov.com
 */
class DefaultFacebookAuthDaoSpec extends Specification {

    static {
        ExpandoMetaClass.enableGlobally()
    }

    DefaultFacebookAuthDao dao
    def grails
    Map securityConfig = [:]

    def setup() {
        grails = new DefaultGrailsApplication()
        grails.metaClass.getDomainClass = {String name ->
            if (TestFacebookUser.canonicalName == name) {
                return TestFacebookUser
            }
            if (TestAppUser.canonicalName == name) {
                return TestAppUser
            }
            if (TestAuthority.canonicalName == name) {
                return TestAuthority
            }
            if (TestRole.canonicalName == name) {
                return TestRole
            }
            println "Uknown domain: $name"
            return null
        }
        dao = new DefaultFacebookAuthDao(
                FacebookUserDomainClazz: TestFacebookUser,
                domainClassName: TestFacebookUser.canonicalName,
                AppUserDomainClazz: TestAppUser,
                appUserConnectionPropertyName: 'user',
                grailsApplication: grails as GrailsApplication
        )
        TestAuthority._calls = []
        TestRole._calls = []
        TestFacebookUser._calls = []
        TestAppUser._calls = []
        securityConfig = [
                userLookup: [
                        authorityJoinClassName: TestRole.canonicalName,
                        usernamePropertyName: 'username',
                        passwordPropertyName: 'password',
                        enabledPropertyName: 'enabled',
                        accountExpiredPropertyName: 'expired',
                        accountLockedPropertyName: 'locked',
                        passwordExpiredPropertyName: 'passwordExpired',
                ],
                authority: [
                        className: TestAuthority.canonicalName,
                        nameField: 'name'
                ]
        ]
        SpringSecurityUtils.metaClass.static.getSecurityConfig = {
            return securityConfig
        }

    }

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

    def "Use service for create"() {
        setup:
        def args = []
        TestFacebookUser user = new TestFacebookUser()
        def service = "temp"
        service.metaClass.create = { FacebookAuthToken token ->
            args << token
            return user
        }
        DefaultFacebookAuthDao dao = new DefaultFacebookAuthDao()
        dao.facebookAuthService = service
        FacebookAuthToken token = new FacebookAuthToken(uid: 1)
        when:
        def act = dao.create(token)
        then:
        act == user
        args == [token]
    }

    def "Basic create"() {
        setup:
        FacebookAuthToken token = new FacebookAuthToken(uid: 1)
        when:
        def act = dao.create(token)
        then:
        act != null
        TestAuthority._calls == [
                ['findByName', 'ROLE_USER'],
                ['findByName', 'ROLE_FACEBOOK']
        ]
        TestRole._calls.size() == 1
        TestRole._calls[0][0] == 'create'
        TestAppUser._calls == [
                ['save', [flush: true, failOnError: true]]
        ]
        TestFacebookUser._calls == [
                ['save', [flush: true, failOnError: true]]
        ]
    }

    def "Call notification methods on create"() {
        setup:
        List calls = []
        FacebookAuthToken token = new FacebookAuthToken(uid: 1)
        def service = "temp"
        service.metaClass.onCreate = { TestFacebookUser a1, FacebookAuthToken a2 ->
            calls << ['onCreate', [a1, a2]]
        }
        service.metaClass.afterCreate = { TestFacebookUser a1, FacebookAuthToken a2 ->
            calls << ['afterCreate', [a1, a2]]
        }
        dao.facebookAuthService = service
        when:
        def act = dao.create(token)
        then:
        calls.size() == 2
        calls[0][0] == 'onCreate'
        calls[1][0] == 'afterCreate'
    }
}
