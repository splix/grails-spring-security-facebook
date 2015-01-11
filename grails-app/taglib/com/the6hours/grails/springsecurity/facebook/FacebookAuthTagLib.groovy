package com.the6hours.grails.springsecurity.facebook

import grails.plugin.springsecurity.SpringSecurityUtils

/**
 * TODO
 *
 * @since 31.03.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */
class FacebookAuthTagLib {

    static namespace = 'facebookAuth'

    static final String MARKER = 'com.the6hours.grails.springsecurity.facebook.FacebookAuthTagLib#init'

    FacebookAuthUtils facebookAuthUtils

    /**
     * Add Facebook Javascript SDK initialization code. You could also provide extra initialization JS in the body of
     * this tag, it will be executed just after Facebook SDK initialization.
     *
     * By default tag executed only once pre page
     *
     * @attr force Force tag to put FB SDK initialization code (even if it's already added)
     *
     */
    Closure init = { attrs, body ->
        Boolean init = request.getAttribute(MARKER) ?: false

        def conf = SpringSecurityUtils.securityConfig.facebook
        if (conf.taglib?.initfb == false) {
            log.debug("FB Init is disabled. Skip")
            return
        }

        if (!init || attrs.force == 'true') {
            String lang = conf.taglib.language
            if (attrs.lang) {
                lang = attrs.lang
            } else if (attrs.language) {
                lang = attrs.language
            }
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

    /**
     * Put Facebook Connect button.
     *
     * @emptyTag
     *
     * @attr type - 'server' or 'client', depends on what type of authorization you would like to use. By default it
     * uses server-side authentication (if such authentication type is enabled)
     * @attr img - url to image for connect button (for server-side authentication only)
     */
    Closure connect = { attrs, body ->
        def writer = getOut()
        if (attrs.type) {
            if (attrs.type == 'server') {
                writer << serverSideConnect(attrs, body)
                return
            }
            if (attrs.type == 'client') {
                writer << clientSideConnect(attrs, body)
                return
            }
            log.error("Invalid connect type: ${attrs.type}")
        }

        if (facebookAuthUtils.filterTypes.contains('redirect')) {
            log.debug("Do default server-side authentication redirect")
            writer << serverSideConnect(attrs, body)
            return
        }

        log.debug("Do default client-side authentication")
        writer << clientSideConnect(attrs, body)
    }

    Closure serverSideConnect = { attrs, body ->
        log.debug("Apply server side connect")
        def writer = getOut()
        def conf = SpringSecurityUtils.securityConfig.facebook
        String target = attrs.startUrl ?: conf.filter.redirect.redirectFromUrl
        String bodyValue = body()
        if (!bodyValue || !bodyValue.trim()) {
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

        if (attrs.skipInit == null || !Boolean.valueOf(attrs.skipInit)) {
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
                permissions = rawPermissions.findAll { it }.collect { it.toString().trim() }.findAll { it }
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
        attrs.each { String attr, value ->
            if (attr.startsWith('img-')) {
                attr = attr.substring('img-'.length())
                used[attr] = value?.toString()
            }
        }
        if (!used.alt) {
            used.alt = conf.taglib.button.text
        }
        used.each { key, value -> buf.append(key).append('="').append(value).append('" ') }
        buf.append("/>")
        buf
    }
}
