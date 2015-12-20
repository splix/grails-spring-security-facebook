package com.the6hours.grails.springsecurity.facebook

/**
 *
 * Since 23.04.13
 * @author Igor Artamonov, http://igorartamonov.com
 */
class TestRole {

    static List _calls = []

    static def withTransaction(Closure c) {
        return c.call()
    }

    static void create(def appUser, def auth) {
        _calls << ['create', [appUser, auth]]
    }

}
