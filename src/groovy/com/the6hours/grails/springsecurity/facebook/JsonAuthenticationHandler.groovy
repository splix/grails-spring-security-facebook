package com.the6hours.grails.springsecurity.facebook

import grails.converters.JSON
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

import javax.servlet.ServletException
import javax.servlet.ServletOutputStream
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 25.01.13
 */
class JsonAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    boolean useJsonp = false
    boolean defaultJsonpCallback = 'jsonpCallback'

    void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
        throws IOException, javax.servlet.ServletException {
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        Map data = [
                authenticated: false,
                message: exception?.message
        ]
        JSON json = new JSON(data)
        if (useJsonp) {
           renderAsJSONP(json, request, response)
        } else {
            json.render(response)
        }
    }

    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        throws IOException, ServletException {
        FacebookAuthToken token = authentication
        Map data = [
                authenticated: true,
                uid: token.uid,
                roles: token.authorities?.collect { it.authority }
        ]
        if (token.principal != null && UserDetails.isAssignableFrom(token.principal.class)) {
            data.username = token.principal.username
            data.enabled = token.principal.enabled
        }
        JSON json = new JSON(data)
        if (useJsonp) {
           renderAsJSONP(json, request, response)
        } else {
            json.render(response)
        }
    }

    void renderAsJSONP(JSON json, HttpServletRequest request, HttpServletResponse response) {
        String callback = this.defaultJsonpCallback
        if (request.getParameterMap().containsKey('callback')) {
            callback = request.getParameter('callback')
        } else if (request.getParameterMap().containsKey('jsonp')) {
            callback = request.getParameter('jsonp')
        }
        response.setContentType('application/javascript')
        String jsonString = json.toString()
        response.setContentLength(callback.bytes.length + 'c'.bytes.length*2 + jsonString.bytes.length)
        ServletOutputStream out = response.outputStream
        out.print(callback)
        out.print('(')
        out.print(jsonString)
        out.print(')')
    }
}
