package com.the6hours.grails.springsecurity.facebook

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 27.12.11
 */
public enum DomainsRelation {

    SameObject,
    JoinedUser

    static DomainsRelation getFrom(Object x) {
        if (x == null) {
            return JoinedUser
        }
        if (x instanceof DomainsRelation) {
            return x
        }
        x = x.toString()
        DomainsRelation found = DomainsRelation.values().find {
            it.name().equalsIgnoreCase(x)
        }
        return found ?: JoinedUser
    }
}