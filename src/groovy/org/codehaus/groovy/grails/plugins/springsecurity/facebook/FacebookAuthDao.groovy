package org.codehaus.groovy.grails.plugins.springsecurity.facebook

public interface FacebookAuthDao {

    FacebookUser create(FacebookAuthToken token)

    void update(FacebookAuthToken token)

    FacebookUser get(long uid)
}