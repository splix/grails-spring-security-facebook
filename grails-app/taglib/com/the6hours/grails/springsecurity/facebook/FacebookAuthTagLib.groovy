package com.the6hours.grails.springsecurity.facebook

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

/**
 * TODO
 *
 * @since 31.03.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */

class FacebookAuthTagLib {

	static namespace = 'facebookAuth'

    static final String MARKER = 'com.the6hours.grails.springsecurity.facebook.FacebookAuthTagLib#init'

	/** Dependency injection for springSecurityService. */
	def springSecurityService

	def connect = { attrs, body ->
        def conf = SpringSecurityUtils.securityConfig.facebook

        Boolean init = request.getAttribute(MARKER)
        if (attrs.requirejs != 'false' && (init == null || !init)) {
            String lang = conf.language
            def appId = conf.appId
            out << '<div id="fb-root"></div>\n'

            out << '<script>\n'

            out << "window.fbAsyncInit = function() {\n"
            out << "  FB.init({\n"
            out << "    appId  : '${appId}',\n"
            out << "    status : true,\n"
            out << "    cookie : true,\n"
            out << "    xfbml  : true,\n"
            out << "    oauth  : true\n"
            out << "  });\n"
            out << "};\n"

            out << '(function(d){'
            out << "var js, id = 'facebook-jssdk'; if (d.getElementById(id)) {return;}"
            out << "js = d.createElement('script'); js.id = id; js.async = true;"
            out << "js.src = \"//connect.facebook.net/${lang}/all.js\";"
            out << "d.getElementsByTagName('head')[0].appendChild(js);"
            out << '}(document));\n'

            out << '</script>\n'

            request.setAttribute(MARKER, true)
        }


        String buttonText = conf.button.text
        if (attrs.text) {
            buttonText = attrs.text
        }

        List permissions = []
        if (attrs.permissions) {
            if (attrs.permissions instanceof Collection) {
                permissions = attrs.permissions.findAll {
                    it != null
                }.collect {
                    it.toString().trim()
                }.findAll {
                    it.length() > 0
                }
            } else {
                permissions = attrs.permissions.toString().split(',').collect { it.trim() }
            }
        }

        boolean showFaces = false

        out << "<div class=\"fb-login-button\" data-scope=\"${permissions.join(', ')}\" data-show-faces=\"${showFaces}\">$buttonText</div>"
    }

}