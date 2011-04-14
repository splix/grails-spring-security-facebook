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
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.plugins.springsecurity.facebook.FacebookAuthProvider
import org.codehaus.groovy.grails.plugins.springsecurity.facebook.FacebookAuthFilter

class SpringSecurityFacebookGrailsPlugin {

   String version = '0.1'
   String grailsVersion = '1.3.3 > *'
   Map dependsOn = ['springSecurityCore': '1.0 > *']

   String author = 'Igor Artamonov'
   String authorEmail = 'igor@artamonov.ru'
   String title = 'Facebook Connect authentication support for the Spring Security plugin.'
   String description = 'Facebook Connect authentication support for the Spring Security plugin.'

   String documentation = 'http://grails.org/plugin/spring-security-facebook'

   def doWithSpring = {

       def SpringSecurityUtils = classLoader.loadClass(
	       'org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils')

	   def conf = SpringSecurityUtils.securityConfig
	   if (!conf) {
		   return
	   }

	   println 'Configuring Spring Security Facebook ...'
	   SpringSecurityUtils.loadSecondaryConfig 'DefaultFacebookSecurityConfig'
	   // have to get again after overlaying DefaultOpenIdSecurityConfig
	   conf = SpringSecurityUtils.securityConfig

	   SpringSecurityUtils.registerProvider conf.beans.provider
	   SpringSecurityUtils.registerFilter conf.beans.filter, SecurityFilterPosition.OPENID_FILTER


	   facebookAuthProvider(FacebookAuthProvider) {
		   userDetailsService = ref('userDetailsService')
	   }

	   facebookAuthFilter(FacebookAuthFilter) {
		   rememberMeServices = ref('rememberMeServices')
		   authenticationManager = ref('authenticationManager')
		   authenticationSuccessHandler = ref('authenticationSuccessHandler')
		   authenticationFailureHandler = ref('authenticationFailureHandler')
		   authenticationDetailsSource = ref('authenticationDetailsSource')
		   sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
		   filterProcessesUrl = '/j_spring_facebook_security_check' // not configurable
	   }

   }

   def doWithApplicationContext = { ctx ->
   }
}
