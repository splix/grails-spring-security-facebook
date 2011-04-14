package grails.plugins.springsecurity

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

/**
 * TODO
 *
 * @since 31.03.11
 * @author Igor Artamonov (http://igorartamonov.com)
 */

class FacebookAuthTagLib {

	static namespace = 'fbSec'

	/** Dependency injection for springSecurityService. */
	def springSecurityService

	def connect = { attrs, body ->
        def conf = SpringSecurityUtils.securityConfig.facebook
        String lang = conf.language
        def appId = conf.appId
        def buttonText = conf.button.text

        out << '<div id="fb-root"></div>'
        out << '<script src="http://connect.facebook.net/$lang/all.js"></script>'
        out << '<script> FB.init({ appId:"$appId", cookie:true, status:true, xfbml:true});</script>'

        out << '<fb:login-button>$buttonText</fb:login-button>'
    }

}