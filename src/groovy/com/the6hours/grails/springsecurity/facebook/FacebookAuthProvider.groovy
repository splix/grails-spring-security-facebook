package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.User
import org.apache.log4j.Logger

public class FacebookAuthProvider implements AuthenticationProvider {

    private static def log = Logger.getLogger(this)

	FacebookAuthDao facebookAuthDao
	boolean createNew = true 

	public Authentication authenticate(Authentication authentication) {
		FacebookAuthToken token = authentication
		
		FacebookUserDomain user = facebookAuthDao.findUser(token.uid)
		
		if (user == null) {
			//log.debug "New person with $token.uid"
			if (createNew) {
				log.info "Create new facebook user with uid $token.uid"
				user = facebookAuthDao.create(token)
			} else {
                log.error "User $token.uid not exists - not authenticated"
                return null
            }
		} else {
			if (token.session != user.session) {
				//User's secret and session can be changed any time
				user.session = token.session
				user.secret = token.secret
				facebookAuthDao.update(user)
			}
		}
        if (user != null) {
            UserDetails userDetails = createUserDetails(user, token.secret)

            token.details = userDetails
            token.principal = facebookAuthDao.getPrincipal(user)
            token.authorities = userDetails.getAuthorities()
        } else {
            token.authenticated = false
        }
		return token
	}

	public boolean supports(Class<? extends Object> authentication) {
		return FacebookAuthToken.isAssignableFrom(authentication);
	}
	
   protected UserDetails createUserDetails(FacebookUserDomain user, String secret) {
	   Collection<GrantedAuthority> roles = facebookAuthDao.getRoles(user)
	   new User(user.uid.toString(), secret, true,
			   true, true, true, roles)
   }

}