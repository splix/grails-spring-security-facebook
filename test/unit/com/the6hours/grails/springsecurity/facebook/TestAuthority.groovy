package com.the6hours.grails.springsecurity.facebook

/**
 *
 * Since 23.04.13
 * @author Igor Artamonov, http://igorartamonov.com
 */
class TestAuthority {

    static _calls = []

    String name

    static TestAuthority findByName(String name) {
        _calls << ['findByName', name]
        if (name == 'ROLE_USER') {
            return new TestAuthority(name: 'ROLE_USER')
        }
        return null
    }

    static def withTransaction(Closure c) {
        return c.call()
    }

}
