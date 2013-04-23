package com.the6hours.grails.springsecurity.facebook

/**
 *
 * Created at 20.04.13
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class TestAppUser {

    static _calls = []

    String username
    String password
    boolean enabled
    boolean expired
    boolean locked
    boolean passwordExpired

    static def withTransaction(Closure c) {
        return c.call()
    }

    def save(def args) {
        _calls << ['save', args]
    }

}
