package com.the6hours.grails.springsecurity.facebook

import grails.test.mixin.TestMixin
import grails.test.mixin.support.GrailsUnitTestMixin
import org.springframework.security.core.authority.SimpleGrantedAuthority
import spock.lang.Specification

import com.the6hours.grails.springsecurity.facebook.FacebookAuthToken

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class FacebookAuthTokenSpec extends Specification {

    def setup() {
    }

    def cleanup() {
    }

    void "authorities should not be null after construction"() {
        when:
        FacebookAuthToken token = new FacebookAuthToken()

        then:
        token.authorities != null
    }

    void "toString works"() {
        when:
        FacebookAuthToken token = new FacebookAuthToken()
        token.authorities = [new SimpleGrantedAuthority('ROLE_USER')]
        token.principal = 'test'
        token.uid = 123456
        def act = token.toString()

        then:
        act == 'Principal: test, uid: 123456, roles: [ROLE_USER]'
    }

    void "toString works with null authorities"() {
        when:
        FacebookAuthToken token = new FacebookAuthToken()
        token.authorities = null
        token.principal = 'test'
        token.uid = 123456
        def act = token.toString()

        then:
        act == 'Principal: test, uid: 123456, roles: null'
    }

    void "toString works with invalid authorities"() {
        when:
        FacebookAuthToken token = new FacebookAuthToken()
        token.authorities = [new SimpleGrantedAuthority('ROLE_USER'), null]
        token.principal = 'test'
        token.uid = 123456
        def act = token.toString()

        then:
        act == 'Principal: test, uid: 123456, roles: [ROLE_USER, null]'
    }
}
