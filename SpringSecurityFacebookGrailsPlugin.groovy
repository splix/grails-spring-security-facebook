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

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.util.Environment
import grails.util.Metadata

import org.slf4j.LoggerFactory

import com.the6hours.grails.springsecurity.facebook.DefaultFacebookAuthDao
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieDirectFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieLogoutHandler
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieTransparentFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthJsonFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthProvider
import com.the6hours.grails.springsecurity.facebook.FacebookAuthRedirectFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthUtils
import com.the6hours.grails.springsecurity.facebook.JsonAuthenticationHandler

class SpringSecurityFacebookGrailsPlugin {

    String version = '0.16.2'
    String grailsVersion = '2.4.0 > *'
    def loadAfter = ['springSecurityCore']
    def license = 'APACHE'

    def developers = [
            //extra developers
    ]
    def issueManagement = [system: "GitHub", url: "https://github.com/splix/grails-spring-security-facebook/issues"]
    def scm = [url: "http://github.com/splix/grails-spring-security-facebook"]

    String author = 'Igor Artamonov'
    String authorEmail = 'igor@artamonov.ru'
    String title = 'Facebook Authentication for Spring Security'
    String description = 'Facebook Authentication for Spring Security Core plugin'

    String documentation = "http://splix.github.io/grails-spring-security-facebook/"

    def organization = [ name: "The 6 Hours", url: "http://the6hours.com/" ]

    def observe = ["springSecurityCore"]

    String _facebookDaoName

    def doWithSpring = {

        if (Environment.current == Environment.TEST) {
            if (Metadata.getCurrent().getApplicationName() == 'spring-security-facebook') {
                println "Test mode. Skipping initial plugin initialization"
                return
            }
            log.debug("Run in test mode")
        }

        def conf = SpringSecurityUtils.securityConfig
        if (!conf) {
            println 'ERROR: There is no Spring Security configuration'
            println 'ERROR: Stop configuring Spring Security Facebook'
            return
        }

        if (!hasProperty('log')) {
            println 'WARN: No such property: log for class: SpringSecurityFacebookGrailsPlugin'
            println 'WARN: Running from a unit test?'
            println 'WARN: Introducing a log property for plugin'
            this.metaClass.log = LoggerFactory.getLogger(SpringSecurityFacebookGrailsPlugin)
        }

        println 'Configuring Spring Security Facebook ...'
        SpringSecurityUtils.loadSecondaryConfig 'DefaultFacebookSecurityConfig'
        // have to get again after overlaying DefaultFacebookecurityConfig
        conf = SpringSecurityUtils.securityConfig

        def copy = conf.facebook.clone()
        ['appId', 'secret', 'apiKey'].each { if (copy[it] != 'Invalid') copy[it] = '********' }
        log.debug "Facebook security config: $copy"

        _facebookDaoName = conf.facebook.bean.dao ?: null
        if (_facebookDaoName == null) {
            _facebookDaoName = 'facebookAuthDao'
            String _appUserConnectionPropertyName = getConfigValue(conf, 'facebook.domain.appUserConnectionPropertyName', 'facebook.domain.connectionPropertyName')
            List<String> _roles = getAsStringList(conf.facebook.autoCreate.roles, 'grails.plugin.springsecurity.facebook.autoCreate.roles')
            facebookAuthDao(DefaultFacebookAuthDao) {
                domainClassName = conf.facebook.domain.classname
                appUserConnectionPropertyName = _appUserConnectionPropertyName
                userDomainClassName = conf.userLookup.userDomainClassName
                rolesPropertyName = conf.userLookup.authoritiesPropertyName
                coreUserDetailsService = ref('userDetailsService')
                defaultRoleNames = _roles
            }
            log.debug "Using default Facebook Auth DAO bean (DefaultFacebookAuthDao) with app user connection property name '$_appUserConnectionPropertyName' and default roles ${_roles}"
        } else {
            log.info("Using provided Facebook Auth DAO bean: $_facebookDaoName")
        }

        List<String> _filterTypes = parseFilterTypes(conf)
        List<String> _requiredPermissions = getAsStringList(conf.facebook.permissions, 'Required Permissions')

        facebookAuthUtils(FacebookAuthUtils) {
            apiKey = conf.facebook.apiKey
            secret = conf.facebook.secret
            applicationId = conf.facebook.appId
            apiVersion = conf.facebook.apiVersion ?: '' //Used unversioned Facebook API by default (for backwards compatibility)
            filterTypes = _filterTypes
            requiredPermissions = _requiredPermissions
        }
        log.debug "facebookAuthUtils filter types $_filterTypes and requiredPermissions $_requiredPermissions"

        SpringSecurityUtils.registerProvider 'facebookAuthProvider'
        boolean _createNew = getConfigValue(conf, 'facebook.autoCreate.enabled') ? conf.facebook.autoCreate.enabled as Boolean : false
        facebookAuthProvider(FacebookAuthProvider) {
            facebookAuthDao = ref(_facebookDaoName)
            facebookAuthUtils = ref('facebookAuthUtils')
            postAuthenticationChecks = ref('postAuthenticationChecks')
            createNew = _createNew
        }
        log.debug "registered facebookAuthProvider as an AuthenticationProvider; createNew: $_createNew"

        addFilters(conf, delegate, _filterTypes)
        println '... finished configuring Spring Security Facebook'
    }

    private List<String> parseFilterTypes(conf) {
        List<String> types

        def typesRaw = conf.facebook.filter.types
        if (!typesRaw) {
            typesRaw = conf.facebook.filter.type
            if (!typesRaw) {
                log.warn("Config options 'grails.plugin.springsecurity.facebook.filter.types' or 'grails.plugin.springsecurity.facebook.filter.type' are empty")
            }
        }

        String defaultType = 'transparent'
        List validTypes = ['transparent', 'cookieDirect', 'redirect', 'json']

        if (!typesRaw) {
            log.error("Invalid Facebook Authentication filters configuration: '$typesRaw'. Should be used on of: $validTypes. Current value will be ignored, and type '$defaultType' will be used instead.")
            types = [defaultType]
        } else if (typesRaw instanceof Collection) {
            types = typesRaw*.toString().findAll { it in validTypes }
        } else if (typesRaw instanceof CharSequence) {
            types = typesRaw.toString().split(',').collect { it.trim() }.findAll { it in validTypes }
        } else {
            log.error("Invalid Facebook Authentication filters configuration, invalid value type: '${typesRaw.getClass()}'. Filter typer should be defined as a Collection or String (comma separated, if you need few filters). Type '$defaultType' will be used instead.")
            types = [defaultType]
        }

        if (!types) {
            log.error("Facebook Authentication filter is not configured. Should be used one of: $validTypes. So '$defaultType' will be used by default.")
            log.error("To configure Facebook Authentication filters you should add to Config.groovy:")
            log.error("grails.plugin.springsecurity.facebook.filter.types='transparent'")
            log.error("or")
            log.error("grails.plugin.springsecurity.facebook.filter.types='redirect,transparent,cookieDirect'")

            types = [defaultType]
        }
        return types
    }

    private void addFilters(conf, delegate, types) {
        int basePosition = conf.facebook.filter.position

        log.debug "SpringSecurityUtils.orderedFilters before registering this plugin's: $SpringSecurityUtils.orderedFilters"

        addFilter.delegate = delegate
        types.eachWithIndex { name, idx ->
            addFilter(conf, name, basePosition + 1 + idx)
        }

        log.debug "SpringSecurityUtils.orderedFilters after registering this plugin's: $SpringSecurityUtils.orderedFilters"
    }

    private addFilter = { conf, String name, int position ->
        if (name == 'transparent') {
            SpringSecurityUtils.registerFilter 'facebookAuthCookieTransparentFilter', position
            facebookAuthCookieTransparentFilter(FacebookAuthCookieTransparentFilter) {
                authenticationManager = ref('authenticationManager')
                facebookAuthUtils = ref('facebookAuthUtils')
                logoutUrl = conf.logout.filterProcessesUrl
                forceLoginParameter = conf.facebook.filter.forceLoginParameter
            }
            log.debug "registerFilter 'facebookAuthCookieTransparentFilter' at position $position; logoutUrl '$conf.logout.filterProcessesUrl', forceLoginParameter '$conf.facebook.filter.forceLoginParameter'"
            facebookAuthCookieLogout(FacebookAuthCookieLogoutHandler) {
                facebookAuthUtils = ref('facebookAuthUtils')
                facebookAuthDao = ref(_facebookDaoName)
            }
            SpringSecurityUtils.registerLogoutHandler('facebookAuthCookieLogout')
            log.debug "registerLogoutHandler 'facebookAuthCookieLogout'"
        } else if (name == 'cookieDirect') {
            String _successHandler = getConfigValue(conf, 'facebook.filter.cookieDirect.successHandler')
            String _failureHandler = getConfigValue(conf, 'facebook.filter.cookieDirect.failureHandler')
            String url = getConfigValue(conf, 'facebook.filter.cookieDirect.processUrl', 'facebook.filter.processUrl')
            SpringSecurityUtils.registerFilter 'facebookAuthCookieDirectFilter', position
            log.debug "registerFilter 'facebookAuthCookieDirectFilter' at position $position; logoutUrl '$conf.logout.filterProcessesUrl', forceLoginParameter '$conf.facebook.filter.forceLoginParameter'"
            facebookAuthCookieDirectFilter(FacebookAuthCookieDirectFilter, url) {
                authenticationManager = ref('authenticationManager')
                rememberMeServices = ref('rememberMeServices')
                facebookAuthUtils = ref('facebookAuthUtils')
                if (_successHandler) {
                    authenticationSuccessHandler = ref(_successHandler)
                }
                if (_failureHandler) {
                    authenticationFailureHandler = ref(_failureHandler)
                }
            }
        } else if (name == 'redirect') {
            SpringSecurityUtils.registerFilter 'facebookAuthRedirectFilter', position
            String successHandler = getConfigValue(conf, 'facebook.filter.redirect.successHandler')
            String failureHandler = getConfigValue(conf, 'facebook.filter.redirect.failureHandler')
            String _url = getConfigValue(conf, 'facebook.filter.redirect.processUrl', 'facebook.filter.processUrl')
            String _redirectFromUrl = getConfigValue(conf, 'facebook.filter.redirect.redirectFromUrl', 'facebook.filter.redirectFromUrl')
            facebookAuthRedirectFilter(FacebookAuthRedirectFilter, _url) {
                authenticationManager = ref('authenticationManager')
                rememberMeServices = ref('rememberMeServices')
                facebookAuthUtils = ref('facebookAuthUtils')
                redirectFromUrl = _redirectFromUrl
                linkGenerator = ref('grailsLinkGenerator')
                if (successHandler) {
                    authenticationSuccessHandler = ref(successHandler)
                }
                if (failureHandler) {
                    authenticationFailureHandler = ref(failureHandler)
                }
            }
            log.debug "registerFilter 'facebookAuthRedirectFilter' at position $position; _redirectFromUrl '$_redirectFromUrl', processUrl '$_url'"
        } else if (name == 'json') {
            SpringSecurityUtils.registerFilter 'facebookAuthJsonFilter', position
            String _url = conf.facebook.filter.json.processUrl
            boolean _jsonp = '_jsonp'.equalsIgnoreCase(conf.facebook.filter.json.type)
            facebookJsonAuthenticationHandler(JsonAuthenticationHandler) {
                useJsonp = _jsonp
            }
            List<String> _methods
            if (_jsonp) {
                _methods = ['GET']
            }
            else {
                _methods = getAsStringList(conf.facebook.filter.json.methods, '**.facebook.filter.json.type')
                _methods = _methods ? _methods*.toUpperCase() : ['POST']
            }
            facebookAuthJsonFilter(FacebookAuthJsonFilter, _url) {
                methods = _methods
                authenticationManager = ref('authenticationManager')
                facebookAuthUtils = ref('facebookAuthUtils')
                authenticationSuccessHandler = ref('facebookJsonAuthenticationHandler')
                authenticationFailureHandler = ref('facebookJsonAuthenticationHandler')
            }
            log.debug "registerFilter 'facebookAuthJsonFilter' at position $position; useJsonp '$_jsonp', processUrl '$_url', methods: $_methods"
        } else {
            log.error("Invalid filter type: $name")
        }
    }

    def onConfigChange = { event ->
        println("Config change")
        SpringSecurityUtils.resetSecurityConfig()
    }

    private getConfigValue(conf, String... values) {
        def flatConf = conf.flatten()
        String key = values.find {
            if (!flatConf.containsKey(it)) {
                return false
            }
            def val = flatConf.get(it)
            if (val == null || (val instanceof ConfigObject && val.isEmpty())) {
                return false
            }
            return true
        }
        key ? flatConf[key] : null
    }

    private List<String> getAsStringList(conf, String paramHumanName) {
        if (conf == null) {
            log.error("Invalid $paramHumanName filters configuration: '$conf'")
            return null
        }
        if (conf instanceof Collection) {
            return conf*.toString()
        }
        if (conf instanceof CharSequence) {
            return conf.toString().split(',').collect { it.trim() }
        }
        log.error("Invalid $paramHumanName filters configuration, invalid value type: '${conf.getClass()}'. Value should be defined as a Collection or String (comma separated)")
        return null
    }
}
