package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.FilterChain
import org.codehaus.groovy.grails.web.mapping.LinkGenerator

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 19.09.12
 */
class FacebookAuthRedirectFilter extends AbstractAuthenticationProcessingFilter {

    FacebookAuthUtils facebookAuthUtils

    String redirectFromUrl

    LinkGenerator linkGenerator

    FacebookAuthRedirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String uri = getCurrentUrl(request)
        if (uri.equals(redirectFromUrl)) {
            response.sendRedirect(facebookAuthUtils.prepareRedirectUrl(getAbsoluteRedirectUrl(), facebookAuthUtils.requiredPermissions))
            return
        }

        super.doFilter(request, response, chain)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String code = request.getParameter('code')
        if (code) {
            logger.debug("Got 'code' from Facebook. Process authentication using this code")
            FacebookAuthToken token = new FacebookAuthToken(
                    code: code,
                    uid: -1,
                    redirectUri: getAbsoluteRedirectUrl()
            )
            return authenticationManager.authenticate(token)
        }
        throw new InvalidRequestException("Request is empty")
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String uri = getCurrentUrl(request)
        return uri.equals(filterProcessesUrl)
    }

    String getCurrentUrl(HttpServletRequest request) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        uri = uri.substring(request.contextPath.length())
        return uri
    }

    String getAbsoluteRedirectUrl() {
        String path = getFilterProcessesUrl()
        linkGenerator.link(uri: path, absolute: true)
    }

}
