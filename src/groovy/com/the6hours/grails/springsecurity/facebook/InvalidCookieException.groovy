package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import org.springframework.security.core.AuthenticationException

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 05.07.12
 */
@CompileStatic
class InvalidCookieException extends AuthenticationException {

    InvalidCookieException(String msg) {
        super(msg)
    }

    InvalidCookieException(String msg, Object extraInformation) {
        super(msg, extraInformation)
    }
}
