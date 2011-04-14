package org.codehaus.groovy.grails.plugins.springsecurity.facebook

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication
import org.apache.commons.lang.StringUtils
import org.apache.commons.codec.digest.*


public class FacebookAuthFilter extends AbstractAuthenticationProcessingFilter {
	
		String apiKey
		String secret
	
		/**
		* List of paramters that are signed by facebook
		*/
		List<String> fbParams = ["access_token", "secret", "uid", "expires", "session_key"]
	
		def FacebookAuthFilter(String url) {
			super(url)
		}
	
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
			String authToken = request.getParameter("access_token");
	
			if (StringUtils.isEmpty(authToken)) {
				return null
			}
	
			StringBuilder buf = new StringBuilder()
			String[] params = request.getParameterNames().findAll { String it -> fbParams.contains(it) }
			params.sort().each { String param ->
				buf.append(param).append('=').append(request.getParameter(param))
			}
			buf.append(secret)
	
			String mysig = DigestUtils.md5Hex(buf.toString())
			String sig = request.getParameter("sig")
	
			if (!mysig.equals(sig)) {
				//log.warn "Signature of [$buf] is $mysig, but sig = $sig"
				return null
			} else {
				//log.debug "Signature is ok"
			}
	
			FacebookAuthToken token = new FacebookAuthToken(
					uid: Long.parseLong(request.getParameter("uid")),
					secret: request.getParameter("secret"),
					session: request.getParameter("session_key")
			)
			token.authenticated = true
			Authentication authentication = getAuthenticationManager().authenticate(token);
			return authentication
		}
	
	}