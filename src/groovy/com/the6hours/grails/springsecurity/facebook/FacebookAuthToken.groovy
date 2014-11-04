package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

@CompileStatic
class FacebookAuthToken extends AbstractAuthenticationToken {

    Long uid
    FacebookAccessToken accessToken
    String code
    String redirectUri

    def principal

    Collection<GrantedAuthority> authorities

    FacebookAuthToken() {
        super([] as Collection<GrantedAuthority>)
    }

    def getCredentials() { uid }

    String toString() {
        "Principal: $principal, uid: $uid, roles: ${authorities.collect { GrantedAuthority it -> it.authority }}"
    }
}
