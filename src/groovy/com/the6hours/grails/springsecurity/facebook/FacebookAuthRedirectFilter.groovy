package com.the6hours.grails.springsecurity.facebook

import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.core.Authentication
import org.springframework.security.web.util.UrlUtils
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
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
    RequestMatcher redirectFromMatcher
    String redirectToUrl

    LinkGenerator linkGenerator

    FacebookAuthRedirectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
        this.redirectToUrl = defaultFilterProcessesUrl
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (redirectFromMatcher.matches(request)) {
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

    String getAbsoluteRedirectUrl() {
        String path = redirectToUrl
        linkGenerator.link(uri: path, absolute: true)
    }

    void setRedirectFromUrl(String redirectFromUrl) {
        this.redirectFromUrl = redirectFromUrl
        this.redirectFromMatcher = new FriendlyFilterProcessUrlRequestMatcher(redirectFromUrl)
    }

    //original matcher from Spring Security is private
    public static final class FriendlyFilterProcessUrlRequestMatcher implements RequestMatcher {
        public final String filterProcessesUrl;

        FriendlyFilterProcessUrlRequestMatcher(String filterProcessesUrl) {
            Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
            Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid redirect URL");
            this.filterProcessesUrl = filterProcessesUrl;
        }

        public boolean matches(HttpServletRequest request) {
            String uri = request.getRequestURI();
            int pathParamIndex = uri.indexOf(';');

            if (pathParamIndex > 0) {
                // strip everything after the first semi-colon
                uri = uri.substring(0, pathParamIndex);
            }

            if ("".equals(request.getContextPath())) {
                return uri.endsWith(filterProcessesUrl);
            }

            return uri.endsWith(request.getContextPath() + filterProcessesUrl);
        }
    }

}
