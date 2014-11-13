package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.authentication.BadCredentialsException
import spock.lang.Specification

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest

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

    def "Encode Params"() {
        expect:
        query == facebookAuthUtils.encodeParams(data)
        where:
        data                        |  query
        [foo: 'bar']                | 'foo=bar'
        [foo: 5151]                 | 'foo=5151'
        [foo: 1, bar: 'baz']        | 'foo=1&bar=baz'
        [foo: 'привет', bar: '100/7%3']  | 'foo=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82&bar=100%2F7%253'
    }

    def "Return null if no cookies"() {
        setup:
        def request = Mock(HttpServletRequest)
        when:
        def act = facebookAuthUtils.getAuthCookie(request)
        then:
        1 * request.getCookies() >> null
        act == null
    }

    def "Get cookie if exists"() {
        setup:
        def request = Mock(HttpServletRequest)
        facebookAuthUtils.applicationId = '123456'
        def cookies = [
                new Cookie('foo', 'bar'),
                new Cookie('fbsr_8888888', 'incorrect cookie'),
                new Cookie('fbsr_123456', 'correct cookie'),
        ]
        when:
        def act = facebookAuthUtils.getAuthCookie(request)
        then:
        _ * request.getCookies() >> cookies
        act != null
        act.value == 'correct cookie'
    }
}
