package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 22.05.12
 */
@CompileStatic
class FacebookAccessToken implements Serializable {

    String accessToken
    Date expireAt

    String toString() {
        'Access token: ' + accessToken + ', expires at ' + expireAt
    }
}
