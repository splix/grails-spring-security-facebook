package org.codehaus.groovy.grails.plugins.springsecurity.facebook

import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUser
import org.springframework.security.core.Authentication
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl

public class FacebookAuthProvider implements AuthenticationProvider {
	
	FacebookAuthDao facebookAuthDao
	boolean createNew = true 

	public Authentication authenticate(Authentication authentication) {
		FacebookAuthToken token = authentication
		
		FacebookUser user = facebookAuthDao.get(token.uid)
		
		if (user == null) {
			//log.debug "New person with $token.uid"
			if (createNew) {
				//log.info "Create new facebook user"
				user = facebookAuthDao.create(token)
			} else {
                //log.error "User $token.uid not exists - not authenticated"
                return null
            }
		} else {
			if (token.session != user.session) {
				//User's secret and session can be changed any time
				user.session = token.session
				user.secret = token.secret
				facebookAuthDao.update(token)
			}
		}
		UserDetails userDetails = createUserDetails(user, token.secret)

		token.details = userDetails
		token.authorities = userDetails.getAuthorities()
		return token
	}

	public boolean supports(Class<? extends Object> authentication) {
		return FacebookAuthToken.isAssignableFrom(authentication);
	}
	
   protected UserDetails createUserDetails(FacebookUser user, String secret) {
	   List<GrantedAuthority> roles = user.roles.collect {
		   new GrantedAuthorityImpl(it)
	   }
	   new GrailsUser(
			   user.uid.toString(), secret, true,
			   true, true, true, roles, user.id)
   }

}