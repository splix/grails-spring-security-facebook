package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

@CompileStatic
interface FacebookUserDomain {

    String getAccessToken()
    void setAccessToken(String accessToken)

    long getUid()
    void setUid(long uid)
}
