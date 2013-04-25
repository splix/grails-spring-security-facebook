package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.authentication.BadCredentialsException
import spock.lang.Specification

/**
 *
 * Since 25.04.13
 * @author Igor Artamonov, http://igorartamonov.com
 */
class FacebookAuthUtilsSpec extends Specification {

    // Test tools:
    //
    // https://developers.facebook.com/tools/echo
    // http://fbapp.herokuapp.com/
    //

    FacebookAuthUtils facebookAuthUtils

    def setup() {
        facebookAuthUtils = new FacebookAuthUtils(
                secret: 'test_secret',
                applicationId: 1000
        )
    }

    def "Can parse valid signed_request"() {
        expect:
        facebookAuthUtils.extractSignedJson(signed_request)
        where:
        signed_request << [
                'HtEfeVZxRwIk1L7cT5cp9dKL2BGo49+CNNkteAROooE.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsInVzZXJfaWQiOiIxIn0',
                'sgVOceUTD7kvvJeBt8cQuJlts24wr7veakS-fQ0pmcc.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImlzc3VlZF9hdCI6MTI4ODk0NzkxOSwidGhlIGFuc3dlciI6NDJ9',
                'D/XUCLgN8NWk7H4bgjSa7o+S9IFwHoLOnCL4aDJwSh0.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsInVzZXJfaWQiOiIxIiwiY29kZSI6ImFzZGZramhhc2Zhc2praGFkc2poa2dhc2Rqa2hnMzRqaGFqaGdhc2RqaGdhZHNmamtoZ2FzZGtqaGczNGtqaGdhc2RqaGdmdmpiIn0'
        ]
    }

    def "Throw exception on invalid signed_request"() {
        when:
        facebookAuthUtils.extractSignedJson(signed_request)
        then:
        BadCredentialsException e = thrown(BadCredentialsException)
        e.message == 'Invalid signature'
        where:
        signed_request << [
                'EfeVZxRwIk1L7cT5cp9dKL2BGo49+CNNkteAROooE.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsInVzZXJfaWQiOiIxIn0',
                'ssssgVOceUTD7kvvJeBt8cQuJlts24wr7veakS-fQ0pmcc.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImlzc3VlZF9hdCI6MTI4ODk0NzkxOSwidGhlIGFuc3dlciI6NDJ9',
        ]
    }

    def "Extract correct json"() {
        setup:
        String signed_request = 'HtEfeVZxRwIk1L7cT5cp9dKL2BGo49+CNNkteAROooE.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsInVzZXJfaWQiOiIxIn0'
        when:
        def json = facebookAuthUtils.extractSignedJson(signed_request)
        then:
        json != null
        json.user_id == '1'
        json.algorithm == "HMAC-SHA256"
    }

    def "Verify valid signature"() {
        expect:
        facebookAuthUtils.verifySign(signature, payload)
        where:
        signature                                      | payload
        'HtEfeVZxRwIk1L7cT5cp9dKL2BGo49+CNNkteAROooE'  | 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsInVzZXJfaWQiOiIxIn0'
        'HtEfeVZxRwIk1L7cT5cp9dKL2BGo49-CNNkteAROooE'  | 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsInVzZXJfaWQiOiIxIn0'
    }
}
