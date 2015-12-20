package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 27.12.11
 */
@CompileStatic
enum DomainsRelation {

    SameObject,
    JoinedUser

    static DomainsRelation getFrom(x) {
        if (!x) {
            return JoinedUser
        }
        if (x instanceof DomainsRelation) {
            return (DomainsRelation)x
        }
        x = x.toString()
        DomainsRelation found = DomainsRelation.values().find { DomainsRelation dr ->
            dr.name().equalsIgnoreCase((String)x)
        }
        found ?: JoinedUser
    }
}