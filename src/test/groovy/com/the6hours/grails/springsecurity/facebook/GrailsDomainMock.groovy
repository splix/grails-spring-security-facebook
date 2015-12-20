package com.the6hours.grails.springsecurity.facebook

/**
 *
 * Since 25.04.13
 * @author Igor Artamonov, http://igorartamonov.com
 */
class GrailsDomainMock {

    Class clazz

    GrailsDomainMock(Class clazz) {
        this.clazz = clazz
    }

    Object newInstance() {
        return clazz.newInstance()
    }
}
