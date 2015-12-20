package com.the6hours.grails.springsecurity.facebook

/**
 *
 * Created at 20.04.13
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class TestFacebookUser {

    static _calls = []

    Long uid
    String accessToken
    Date accessTokenExpires

    TestAppUser user

    static withTransaction(Closure c) {
        c.call()
    }

    def save(args) {
        _calls << ['save', args]
    }
}
