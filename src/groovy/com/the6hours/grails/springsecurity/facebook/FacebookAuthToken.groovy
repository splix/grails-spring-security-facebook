package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AbstractAuthenticationToken

public class FacebookAuthToken extends AbstractAuthenticationToken implements Authentication, Serializable {
	
	long uid
    FacebookAccessToken accessToken
    String code
    String redirectUri

    Object principal
	
	Collection<GrantedAuthority> authorities
	
	def FacebookAuthToken() {
		super([] as Collection<GrantedAuthority>);
	}	

	public Object getCredentials() {
		return uid;
	}

    String toString() {
        return "Principal: $principal, uid: $uid, roles: ${authorities.collect { it.authority}}"
    }

}