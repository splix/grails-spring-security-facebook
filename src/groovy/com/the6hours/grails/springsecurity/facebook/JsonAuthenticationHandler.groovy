package com.the6hours.grails.springsecurity.facebook

import grails.converters.JSON
import groovy.transform.CompileStatic
import groovy.transform.TypeCheckingMode
import org.springframework.security.core.GrantedAuthority

import javax.servlet.ServletException
import javax.servlet.ServletOutputStream
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 25.01.13
 */
@CompileStatic
class JsonAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler, InitializingBean, ApplicationContextAware {

    private static final Logger log = LoggerFactory.getLogger(this)

    ApplicationContext applicationContext

    boolean useJsonp = false
    boolean defaultJsonpCallback = 'jsonpCallback'
    def facebookAuthService

    void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {

        response.status = HttpServletResponse.SC_UNAUTHORIZED
        Map data = [authenticated: false, message: exception?.message]

        data = callAuthServiceOnJsonFailure(data, exception)
        JSON json = new JSON(data)
        if (useJsonp) {
           renderAsJSONP(json, request, response)
        } else {
            json.render(response)
        }
    }

    @CompileStatic(TypeCheckingMode.SKIP)
    protected Map callAuthServiceOnJsonFailure(Map data, AuthenticationException exception) {
        if (facebookAuthService?.respondsTo('onJsonFailure')) {
            def data2 = facebookAuthService.onJsonFailure(data, exception)
            if (data2) {
                data = data2
            }
        }
        data
    }

    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        throws IOException, ServletException {

        FacebookAuthToken token = (FacebookAuthToken)authentication
        Map data = [authenticated: true, uid: token.uid, roles: token.authorities?.collect { GrantedAuthority it -> it.authority }]
        if (token.principal instanceof UserDetails) {
            data.username = ((UserDetails)token.principal).username
            data.enabled = ((UserDetails)token.principal).enabled
        }
        data = callAuthServiceOnJsonSuccess(data, authentication)
        JSON json = new JSON(data)
        if (useJsonp) {
           renderAsJSONP(json, request, response)
        } else {
            json.render(response)
        }
    }

    @CompileStatic(TypeCheckingMode.SKIP)
    protected Map callAuthServiceOnJsonSuccess(Map data, Authentication authentication) {
        if (facebookAuthService?.respondsTo('onJsonSuccess')) {
            def data2 = facebookAuthService.onJsonSuccess(data, authentication)
            if (data2) {
                data = data2
            }
        }
        data
    }

    void renderAsJSONP(JSON json, HttpServletRequest request, HttpServletResponse response) {
        String callback = defaultJsonpCallback
        if (request.getParameterMap().containsKey('callback')) {
            callback = request.getParameter('callback')
        } else if (request.getParameterMap().containsKey('jsonp')) {
            callback = request.getParameter('jsonp')
        }

		  String jsonString = json.toString()

		  response.setContentType('application/javascript')
        response.setContentLength(callback.bytes.length + 'c'.bytes.length * 2 + jsonString.bytes.length)
        response.outputStream << callback << '(' << jsonString << ')'
    }

    void afterPropertiesSet() {
        if (facebookAuthService) {
            return
        }

        if (applicationContext.containsBean('facebookAuthService')) {
            log.debug("Use provided facebookAuthService")
            facebookAuthService = applicationContext.getBean('facebookAuthService')
        }
    }
}
