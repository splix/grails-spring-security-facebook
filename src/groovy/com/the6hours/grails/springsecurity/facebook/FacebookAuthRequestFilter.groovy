package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 19.09.12
 */
class FacebookAuthRequestFilter extends AbstractAuthenticationProcessingFilter {

    FacebookAuthUtils facebookAuthUtils

    FacebookAuthRequestFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String signedRequest = request.getParameter('signedRequest')
        if (signedRequest) {
            FacebookAuthToken token = facebookAuthUtils.build(signedRequest)
            return authenticationManager.authenticate(token)
        }
        String code = request.getParameter('code')
        if (code) {
            FacebookAuthToken token = new FacebookAuthToken(
                    code: code,
                    uid: -1
            )
            return authenticationManager.authenticate(token)
        }
        throw new InvalidRequestException("Request is empty")
    }
}
