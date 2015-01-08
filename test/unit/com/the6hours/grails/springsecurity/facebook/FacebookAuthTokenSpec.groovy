package com.the6hours.grails.springsecurity.facebook

import grails.test.mixin.TestMixin
import grails.test.mixin.support.GrailsUnitTestMixin
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
		given:
		FacebookAuthToken token = new FacebookAuthToken()
		
		expect:
		token.authorities != null 
    }
}
