package com.the6hours.grails.springsecurity.facebook

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.web.mapping.LinkGenerator
import grails.plugins.springsecurity.SpringSecurityService

/**
 * TODO
 *
 * @since 31.03.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */

class FacebookAuthTagLib {

	static namespace = 'facebookAuth'

    static final String MARKER = 'com.the6hours.grails.springsecurity.facebook.FacebookAuthTagLib#init'

	//SpringSecurityService springSecurityService

    FacebookAuthUtils facebookAuthUtils

    Closure init = { attrs, body ->
        Boolean init = request.getAttribute(MARKER)
        if (init == null) {
            init = false
        }

        def conf = SpringSecurityUtils.securityConfig.facebook
        if (conf.taglib?.initfb == false) {
            log.debug("FB Init is disabled. Skip")
            return
        }

        if (!init || attrs.force == 'true') {
            String lang = conf.taglib.language
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


            out << body.call()

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
    }

    Closure connect = { attrs, body ->
    	def writer = getOut()
        if (attrs.type) {
            if (attrs.type == 'server') {
                writer << serverSideConnect(attrs, body)
                return
            } else if (attrs.type == 'client') {
                writer << clientSideConnect(attrs, body)
                return
            } else {
                log.error("Invalid connect type: ${attrs.type}")
            }
        }

        if (facebookAuthUtils.filterTypes.contains('redirect')) {
            log.debug("Do default server-side authentication redirect")
            writer << serverSideConnect(attrs, body)
            return
        } else {
            log.debug("Do default client-side authentication")
            writer << clientSideConnect(attrs, body)
            return
        }
    }

    Closure serverSideConnect = { attrs, body ->
        log.debug("Apply server side connect")
        def writer = getOut()
        def conf = SpringSecurityUtils.securityConfig.facebook
        String target = conf.filter.redirect.redirectFromUrl
        String bodyValue = body()
        if (bodyValue == null || bodyValue.trim().length() == 0) {
            String imgUrl
            if (attrs.img) {
                imgUrl = attrs.img
            } else if (conf.taglib.button.img) {
                imgUrl = resource(file: conf.taglib.button.img)
            } else {
                imgUrl = resource(file: conf.taglib.button.defaultImg, plugin: 'spring-security-facebook')
            }
            bodyValue = img(attrs, imgUrl)
        }
        Closure newBody = {
            return bodyValue
        }
        writer << link([uri: target], newBody)
    }

    Closure clientSideConnect = { attrs, body ->
        def conf = SpringSecurityUtils.securityConfig.facebook

        if (attrs.skipInit != 'false') {
            init(attrs, body)
        }

        String buttonText = conf.taglib.button.text
        if (attrs.text) {
            buttonText = attrs.text
        }

        List permissions = []
        def rawPermissions
        if (attrs.permissions) {
            rawPermissions = attrs.permissions
        } else {
            rawPermissions = facebookAuthUtils.requiredPermissions
        }
        if (rawPermissions) {
            if (rawPermissions instanceof Collection) {
                permissions = rawPermissions.findAll {
                    it != null
                }.collect {
                    it.toString().trim()
                }.findAll {
                    it.length() > 0
                }
            } else {
                permissions = rawPermissions.toString().split(',').collect { it.trim() }
            }
        } else {
            log.debug("Permissions aren't configured")
        }

        boolean showFaces = false

        out << "<div class=\"fb-login-button\" data-scope=\"${permissions.join(', ')}\" data-show-faces=\"${showFaces}\">$buttonText</div>"
    }

    private String img(Map attrs, String src) {
        def conf = SpringSecurityUtils.securityConfig.facebook

        StringBuilder buf = new StringBuilder()
        buf.append('<img src="').append(src).append('" ')
        Map used = [:]
        attrs.entrySet().each { Map.Entry it ->
            if (it.key in ['height', 'width', 'img-class', 'img-style', 'img-id', 'alt']) {
                String attr = it.key
                if (attr.startsWith('img-')) {
                    attr = attr.substring('img-'.length())
                }
                used[attr] = it.value?.toString()
            }
        }
        if (!used.alt) {
            used.alt = conf.taglib.button.text
        }
        used.entrySet().each { Map.Entry it ->
            buf.append(it.key).append('="').append(it.value).append('" ')
        }
        buf.append("/>")
        return buf.toString()
    }
}
