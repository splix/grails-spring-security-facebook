package com.the6hours.grails.springsecurity.facebook

/**
 *
 * Created at 20.04.13
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class TestFacebookUser {

    long uid
    String accessToken
    Date accessTokenExpires

    TestAppUser user

    static def withTransaction(Closure c) {
        return c.call()
    }
}
