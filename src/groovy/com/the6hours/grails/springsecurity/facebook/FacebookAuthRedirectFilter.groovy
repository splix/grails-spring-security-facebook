package com.the6hours.grails.springsecurity.facebook

import groovy.util.logging.Commons

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.codehaus.groovy.grails.web.mapping.LinkGenerator
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 19.09.12
 */
@Commons
class FacebookAuthRedirectFilter extends AbstractAuthenticationProcessingFilter {

    FacebookAuthUtils facebookAuthUtils

    String redirectFromUrl

    LinkGenerator linkGenerator

    FacebookAuthRedirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String code = request.getParameter('code')
        if (code) {
            logger.debug("Got 'code' from Facebook. Process authentication using this code")
			def redirectAfterLogin = request.getParameter("redirectAfterLogin")
			if (redirectAfterLogin){
				//for security reasons, only the relative paths are allowed
				if (!redirectAfterLogin.startsWith('/')){
					log.warn("The redirect parameter with value $redirectAfterLogin should point to a relative path")
				}
			}
            FacebookAuthToken token = new FacebookAuthToken(
                    code: code,
                    uid: -1,
                    redirectUri: getAbsoluteRedirectUrl(redirectAfterLogin)
            )
			log.debug "Authenticate using the manager"
            return authenticationManager.authenticate(token)
        }
        throw new InvalidRequestException("Request is empty")
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		log.info "requires authentication"
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        uri = uri.substring(request.contextPath.length())
		
		def redirectAfterLogin = request.getParameter("redirectAfterLogin")
		
        if (uri.equals(redirectFromUrl)) {
			log.info "Redirecting"
            response.sendRedirect(facebookAuthUtils.prepareRedirectUrl(getAbsoluteRedirectUrl(), redirectAfterLogin, facebookAuthUtils.requiredPermissions))
            return false
        }

		log.info "Not redirecting"
        return uri.equals(filterProcessesUrl)
    }

    String getAbsoluteRedirectUrl(String redirectAfterLogin) {
        String path = getFilterProcessesUrl()
		if (redirectAfterLogin){
			path += path.contains('?')? '&' : '?'
			path += "redirectAfterLogin=" +  URLEncoder.encode(redirectAfterLogin, 'UTF-8')
			//see http://stackoverflow.com/questions/4386691/facebook-error-error-validating-verification-code
		}
		
        linkGenerator.link(uri: path, absolute: true)
    }

}
