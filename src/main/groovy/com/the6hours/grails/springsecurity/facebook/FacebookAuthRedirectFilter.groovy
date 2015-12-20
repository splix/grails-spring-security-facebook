package com.the6hours.grails.springsecurity.facebook

import groovy.transform.CompileStatic

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.codehaus.groovy.grails.web.mapping.LinkGenerator
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.UrlUtils
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 19.09.12
 */
@CompileStatic
class FacebookAuthRedirectFilter extends AbstractAuthenticationProcessingFilter {

    FacebookAuthUtils facebookAuthUtils
    LinkGenerator linkGenerator
	 RequestMatcher redirectFromMatcher

    String redirectFromUrl
    String redirectToUrl

    FacebookAuthRedirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
        this.redirectToUrl = defaultFilterProcessesUrl
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (redirectFromMatcher.matches((HttpServletRequest)request)) {
            ((HttpServletResponse)response).sendRedirect(
                facebookAuthUtils.prepareRedirectUrl(absoluteRedirectUrl, facebookAuthUtils.requiredPermissions))
        }
		  else {
			  super.doFilter(request, response, chain)
        }
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String code = request.getParameter('code')
        if (!code) {
            throw new InvalidRequestException("Request is empty")
        }

        logger.debug("Got 'code' from Facebook. Process authentication using this code")
        authenticationManager.authenticate new FacebookAuthToken(code: code, uid: -1L, redirectUri: getAbsoluteRedirectUrl())
    }

    String getAbsoluteRedirectUrl() {
        linkGenerator.link(uri: redirectToUrl, absolute: true)
    }

    void setRedirectFromUrl(String redirectFromUrl) {
        this.redirectFromUrl = redirectFromUrl
        this.redirectFromMatcher = new FriendlyFilterProcessUrlRequestMatcher(redirectFromUrl)
    }

    //original matcher from Spring Security is private
    static final class FriendlyFilterProcessUrlRequestMatcher implements RequestMatcher {
        public final String filterProcessesUrl

        FriendlyFilterProcessUrlRequestMatcher(String filterProcessesUrl) {
            Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified")
            Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), "$filterProcessesUrl isn't a valid redirect URL")
            this.filterProcessesUrl = filterProcessesUrl
        }

        boolean matches(HttpServletRequest request) {
            String uri = request.requestURI
            int pathParamIndex = uri.indexOf(';')

            if (pathParamIndex > 0) {
                // strip everything after the first semi-colon
                uri = uri.substring(0, pathParamIndex)
            }

            if (request.contextPath) {
                StringBuilder expectedPath = new StringBuilder()
                expectedPath.append(request.contextPath).append(filterProcessesUrl)
                return uri.endsWith(expectedPath.toString())
            }
            return uri.endsWith(filterProcessesUrl)
        }
    }
}
