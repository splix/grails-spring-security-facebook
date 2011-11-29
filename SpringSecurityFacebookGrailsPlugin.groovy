/* Copyright 2006-2010 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
import com.the6hours.grails.springsecurity.facebook.FacebookAuthProvider
import com.the6hours.grails.springsecurity.facebook.FacebookAuthDirectFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthUtils
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieLogoutHandler

class SpringSecurityFacebookGrailsPlugin {

   String version = '0.3'
   String grailsVersion = '1.3.7 > *'
   Map dependsOn = ['springSecurityCore': '1.0 > *']

   String author = 'Igor Artamonov'
   String authorEmail = 'igor@artamonov.ru'
   String title = 'Facebook Connect authentication support for the Spring Security plugin.'
   String description = 'Facebook Connect authentication support for the Spring Security plugin.'

   String documentation = 'http://grails.org/plugin/spring-security-facebook'

   def doWithSpring = {

       def conf = SpringSecurityUtils.securityConfig
       if (!conf) {
           println 'ERROR: There is no Spring Security configuration'
           println 'ERROR: Stop configuring Spring Security Facebook'
           return
       }

	   println 'Configuring Spring Security Facebook ...'
	   SpringSecurityUtils.loadSecondaryConfig 'DefaultFacebookSecurityConfig'
	   // have to get again after overlaying DefaultOpenIdSecurityConfig
	   conf = SpringSecurityUtils.securityConfig

       if (!conf.facebook.bean.dao) {
           println 'ERROR: There is no dao configired for Facebook Auth'
           println 'ERROR: Stop configuring Spring Security Facebook'
           return
       }

       facebookAuthUtils(FacebookAuthUtils) {
           apiKey = conf.facebook.apiKey
           secret = conf.facebook.secret
           applicationId = conf.facebook.appId
       }

       SpringSecurityUtils.registerProvider 'facebookAuthProvider'
	   facebookAuthProvider(FacebookAuthProvider) {
           facebookAuthDao = ref(conf.facebook.bean.dao)
	   }

       int position = conf.facebook.filter.position
       SpringSecurityUtils.registerFilter 'facebookAuthDirectFilter', position
	   facebookAuthDirectFilter(FacebookAuthDirectFilter, '/j_spring_facebook_security_check') {
		   rememberMeServices = ref('rememberMeServices')
		   authenticationManager = ref('authenticationManager')
		   authenticationSuccessHandler = ref('authenticationSuccessHandler')
		   authenticationFailureHandler = ref('authenticationFailureHandler')
		   authenticationDetailsSource = ref('authenticationDetailsSource')
		   sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
           facebookAuthUtils = ref('facebookAuthUtils')
	   }

       SpringSecurityUtils.registerFilter 'facebookAuthCookieFilter', position + 1
       facebookAuthCookieFilter(FacebookAuthCookieFilter) {
           authenticationManager = ref('authenticationManager')
           facebookAuthUtils = ref('facebookAuthUtils')
           logoutUrl = conf.logout.filterProcessesUrl
       }
       facebookAuthCookieLogout(FacebookAuthCookieLogoutHandler) {
           facebookAuthUtils = ref('facebookAuthUtils')
       }
       SpringSecurityUtils.registerLogoutHandler('facebookAuthCookieLogout')
   }

   def doWithApplicationContext = { ctx ->
   }
}
