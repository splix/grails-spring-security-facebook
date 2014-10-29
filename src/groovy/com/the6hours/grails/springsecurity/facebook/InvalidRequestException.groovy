package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import org.springframework.security.core.AuthenticationException

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 19.09.12
 */
@CompileStatic
class InvalidRequestException extends AuthenticationException {

    InvalidRequestException(String msg, Throwable t) {
        super(msg, t)
    }

    InvalidRequestException(String msg) {
        super(msg)
    }
}
