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

import com.the6hours.grails.springsecurity.facebook.DomainsRelation
import com.the6hours.grails.springsecurity.facebook.FacebookAuthJsonFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthJsonFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthProvider
import com.the6hours.grails.springsecurity.facebook.FacebookAuthJsonFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieTransparentFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthUtils
import com.the6hours.grails.springsecurity.facebook.JsonAuthenticationHandler
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieLogoutHandler
import com.the6hours.grails.springsecurity.facebook.DefaultFacebookAuthDao
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieDirectFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthRedirectFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthRedirectFilter

class SpringSecurityFacebookGrailsPlugin {

   String version = '0.10.4'
   String grailsVersion = '2.0.0 > *'
   Map dependsOn = ['springSecurityCore': '1.2.7.2 > *']

   def license = 'APACHE'

   def developers = [
       //extra developers
   ]
   def issueManagement = [ system: "GitHub", url: "https://github.com/splix/grails-spring-security-facebook/issues" ]
   def scm = [ url: "git@github.com:splix/grails-spring-security-facebook.git" ]

   String author = 'Igor Artamonov'
   String authorEmail = 'igor@artamonov.ru'
   String title = 'Facebook Authentication'
   String description = 'Facebook Connect authentication support for the Spring Security plugin.'

   String documentation = 'http://splix.github.com/grails-spring-security-facebook/'

   def observe = ["springSecurityCore"]

   def doWithSpring = {

       def conf = SpringSecurityUtils.securityConfig
       if (!conf) {
           println 'ERROR: There is no Spring Security configuration'
           println 'ERROR: Stop configuring Spring Security Facebook'
           return
       }

	   println 'Configuring Spring Security Facebook ...'
	   SpringSecurityUtils.loadSecondaryConfig 'DefaultFacebookSecurityConfig'
	   // have to get again after overlaying DefaultFacebookecurityConfig
	   conf = SpringSecurityUtils.securityConfig

       String facebookDaoName = conf?.facebook?.bean?.dao ?: null
       if (facebookDaoName == null) {
           facebookDaoName = 'facebookAuthDao'
           facebookAuthDao(DefaultFacebookAuthDao) {
               domainClassName = conf.facebook.domain.classname
               appUserConnectionPropertyName = conf.facebook.domain.appUserConnectionPropertyName ?: conf.facebook.domain.connectionPropertyName
               userDomainClassName = conf.userLookup.userDomainClassName
               rolesPropertyName = conf.userLookup.authoritiesPropertyName
               coreUserDetailsService = ref('userDetailsService')
               if (conf.facebook.domain.relation) {
                   domainsRelation = DomainsRelation.getFrom(conf.facebook.domain.relation)
               }
           }
       } else {
           log.info("Using provided Facebook Auth DAO bean: $facebookDaoName")
       }

       List<String> _filterTypes = parseFilterTypes(conf)
       List<String> _requiredPermissions = getAsStringList(conf.facebook.permissions, 'Required Permissions', 'facebook.permissions')

       facebookAuthUtils(FacebookAuthUtils) {
           apiKey = conf.facebook.apiKey
           secret = conf.facebook.secret
           applicationId = conf.facebook.appId
           filterTypes = _filterTypes
           requiredPermissions = _requiredPermissions
       }

       SpringSecurityUtils.registerProvider 'facebookAuthProvider'
	   facebookAuthProvider(FacebookAuthProvider) {
           facebookAuthDao = ref(facebookDaoName)
           facebookAuthUtils = ref('facebookAuthUtils')
	   }

       addFilters(conf, delegate, _filterTypes)
   }

   private List<String> getAsStringList(def conf, String paramHumanName, String paramName) {
       def raw = conf

       if (raw == null) {
           log.error("Invalid $paramHumanName filters configuration: '$raw'")
       } else if (raw instanceof Collection) {
           return raw.collect { it.toString() }
       } else if (raw instanceof String) {
           return raw.split(',').collect { it.trim() }
       } else {
           log.error("Invalid $paramHumanName filters configuration, invalid value type: '${raw.getClass()}'. Value should be defined as a Collection or String (comma separated, if you need few filters)")
       }
       return null
   }

   private List<String> parseFilterTypes(def conf) {
       def typesRaw = conf.facebook.filter.types
       List<String> types = null
       if (!typesRaw) {
           log.warn("Value for 'grails.plugins.springsecurity.facebook.filter.types' is empty")
           typesRaw = conf.facebook.filter.type
       }

       String defaultType = 'transparent'
       List validTypes = ['transparent', 'cookieDirect', 'redirect', 'json']

       if (!typesRaw) {
           log.error("Invalid Facebook Authentication filters configuration: '$typesRaw'. Should be used on of: $validTypes. Current value will be ignored, and type '$defaultType' will be used instead.")
           types = [defaultType]
       } else if (typesRaw instanceof Collection) {
           types = typesRaw.collect { it.toString() }.findAll { it in validTypes }
       } else if (typesRaw instanceof String) {
           types = typesRaw.split(',').collect { it.trim() }.findAll { it in validTypes }
       } else {
           log.error("Invalid Facebook Authentication filters configuration, invalid value type: '${typesRaw.getClass()}'. Filter typer should be defined as a Collection or String (comma separated, if you need few filters). Type '$defaultType' will be used instead.")
           types = [defaultType]
       }

       if (!types || types.empty) {
           log.error("Facebook Authentication filter is not configured. Should be used one of: $validTypes. So '$defaultType' will be used by default.")
           log.error("To configure Facebook Authentication filters you should add to Config.groovy:")
           log.error("grails.plugins.springsecurity.facebook.filter.types='transparent'")
           log.error("or")
           log.error("grails.plugins.springsecurity.facebook.filter.types='redirect,transparent,cookieDirect'")

           types = [defaultType]
       }
       return types
   }

   private void addFilters(def conf, def delegate, def types) {
       int basePosition = conf.facebook.filter.position

       addFilter.delegate = delegate
       types.eachWithIndex { name, idx ->
           addFilter(conf, name, basePosition + 1 + idx)
       }
   }

   private addFilter = { def conf, String name, int position ->
       if (name == 'transparent') {
           SpringSecurityUtils.registerFilter 'facebookAuthCookieTransparentFilter', position
           facebookAuthCookieTransparentFilter(FacebookAuthCookieTransparentFilter) {
               authenticationManager = ref('authenticationManager')
               facebookAuthUtils = ref('facebookAuthUtils')
               logoutUrl = conf.logout.filterProcessesUrl
               forceLoginParameter = conf.facebook.filter.forceLoginParameter
           }
           facebookAuthCookieLogout(FacebookAuthCookieLogoutHandler) {
               facebookAuthUtils = ref('facebookAuthUtils')
           }
           SpringSecurityUtils.registerLogoutHandler('facebookAuthCookieLogout')
       } else if (name == 'cookieDirect') {
           SpringSecurityUtils.registerFilter 'facebookAuthCookieDirectFilter', position
           facebookAuthCookieDirectFilter(FacebookAuthCookieDirectFilter, conf.facebook.filter.processUrl) {
               authenticationManager = ref('authenticationManager')
               facebookAuthUtils = ref('facebookAuthUtils')
           }
       } else if (name == 'redirect') {
           SpringSecurityUtils.registerFilter 'facebookAuthRedirectFilter', position
           facebookAuthRedirectFilter(FacebookAuthRedirectFilter, conf.facebook.filter.processUrl) {
               authenticationManager = ref('authenticationManager')
               facebookAuthUtils = ref('facebookAuthUtils')
               redirectFromUrl = conf.facebook.filter.redirectFromUrl
               linkGenerator = ref('grailsLinkGenerator')
           }
       } else if (name == 'json') {
           SpringSecurityUtils.registerFilter 'facebookAuthJsonFilter', position
           String url = conf.facebook.filter.json.processUrl
           facebookJsonAuthenticationHandler(JsonAuthenticationHandler) {
           }
           facebookAuthJsonFilter(FacebookAuthJsonFilter, url) {
               authenticationManager = ref('authenticationManager')
               facebookAuthUtils = ref('facebookAuthUtils')
               authenticationSuccessHandler = ref('facebookJsonAuthenticationHandler')
               authenticationFailureHandler = ref('facebookJsonAuthenticationHandler')
           }
       } else {
           log.error("Invalid filter type: $name")
       }
   }

   def doWithApplicationContext = { ctx ->
   }

    def onConfigChange = { event ->
        println("Config change")
		SpringSecurityUtils.resetSecurityConfig()

	}
}
