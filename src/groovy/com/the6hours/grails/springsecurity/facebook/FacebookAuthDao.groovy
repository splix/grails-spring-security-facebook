package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.GrantedAuthority

public interface FacebookAuthDao {

    FacebookUserDomain findUser(long uid)

    FacebookUserDomain create(FacebookAuthToken token)

    void update(FacebookUserDomain user)

    Object getPrincipal(FacebookUserDomain user)

    Collection<GrantedAuthority> getRoles(FacebookUserDomain user)

}