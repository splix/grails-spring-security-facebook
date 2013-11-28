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
import com.the6hours.grails.springsecurity.facebook.FacebookAuthProvider
import com.the6hours.grails.springsecurity.facebook.FacebookAuthJsonFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieTransparentFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthUtils
import com.the6hours.grails.springsecurity.facebook.JsonAuthenticationHandler
import grails.util.Environment
import grails.util.Metadata
import grails.plugin.springsecurity.SpringSecurityUtils
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieLogoutHandler
import com.the6hours.grails.springsecurity.facebook.DefaultFacebookAuthDao
import com.the6hours.grails.springsecurity.facebook.FacebookAuthCookieDirectFilter
import com.the6hours.grails.springsecurity.facebook.FacebookAuthRedirectFilter

class SpringSecurityFacebookGrailsPlugin {

    String version = '0.15.2-CORE2'
    String grailsVersion = '2.0.0 > *'
    Map dependsOn = ['springSecurityCore': '2.0-RC2> *']

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
            } else {
                log.debug("Run in test mode")
            }
        }

        def conf = SpringSecurityUtils.securityConfig
        if (!conf) {
            println 'ERROR: There is no Spring Security configuration'
            println 'ERROR: Stop configuring Spring Security Facebook'
            return
        }

        if (!this.hasProperty('log')) {
            println 'WARN: No such property: log for class: SpringSecurityFacebookGrailsPlugin'
            println 'WARN: Running from a unit test?'
            println 'WARN: Introducing a log property for plugin'
            this.metaClass.log = org.apache.commons.logging.LogFactory.getLog(SpringSecurityFacebookGrailsPlugin)
        }

        println 'Configuring Spring Security Facebook ...'
        SpringSecurityUtils.loadSecondaryConfig 'DefaultFacebookSecurityConfig'
        // have to get again after overlaying DefaultFacebookecurityConfig
        conf = SpringSecurityUtils.securityConfig

        _facebookDaoName = conf?.facebook?.bean?.dao ?: null
        if (_facebookDaoName == null) {
            _facebookDaoName = 'facebookAuthDao'
            String _appUserConnectionPropertyName = getConfigValue(conf, 'facebook.domain.appUserConnectionPropertyName', 'facebook.domain.connectionPropertyName')
            List<String> _roles = getAsStringList(conf.facebook.autoCreate.roles, 'grails.plugins.springsecurity.facebook.autoCreate.roles')
            facebookAuthDao(DefaultFacebookAuthDao) {
                domainClassName = conf.facebook.domain.classname
                appUserConnectionPropertyName = _appUserConnectionPropertyName
                userDomainClassName = conf.userLookup.userDomainClassName
                rolesPropertyName = conf.userLookup.authoritiesPropertyName
                coreUserDetailsService = ref('userDetailsService')
                defaultRoleNames = _roles
            }
        } else {
            log.info("Using provided Facebook Auth DAO bean: $_facebookDaoName")
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
        boolean _createNew = getConfigValue(conf, 'facebook.autoCreate.enabled') ? conf.facebook.autoCreate.enabled as Boolean : false
        facebookAuthProvider(FacebookAuthProvider) {
            facebookAuthDao = ref(_facebookDaoName)
            facebookAuthUtils = ref('facebookAuthUtils')
            createNew = _createNew
        }

        addFilters(conf, delegate, _filterTypes)
        println '... finished configuring Spring Security Facebook'
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
                facebookAuthDao = ref(_facebookDaoName)
            }
            SpringSecurityUtils.registerLogoutHandler('facebookAuthCookieLogout')
        } else if (name == 'cookieDirect') {
            String _successHandler = getConfigValue(conf, 'facebook.filter.cookieDirect.successHandler')
            String _failureHandler = getConfigValue(conf, 'facebook.filter.cookieDirect.failureHandler')
            String url = getConfigValue(conf, 'facebook.filter.cookieDirect.processUrl', 'facebook.filter.processUrl')
            SpringSecurityUtils.registerFilter 'facebookAuthCookieDirectFilter', position
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
        } else if (name == 'json') {
            SpringSecurityUtils.registerFilter 'facebookAuthJsonFilter', position
            String _url = conf.facebook.filter.json.processUrl
            boolean _jsonp = '_jsonp'.equalsIgnoreCase(conf.facebook.filter.json.type)
            facebookJsonAuthenticationHandler(JsonAuthenticationHandler) {
                useJsonp = _jsonp
            }
            List<String> _methods = getAsStringList(conf.facebook.filter.json.methods, '**.facebook.filter.json.type')
            _methods = _methods ? _methods*.toUpperCase() : ['POST']
            if (_jsonp) {
                _methods = ['GET']
            }
            facebookAuthJsonFilter(FacebookAuthJsonFilter, _url) {
                methods = _methods
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

    private Object getConfigValue(def conf, String... values) {
        conf = conf.flatten()
        String key = values.find {
            if (!conf.containsKey(it)) {
                return false
            }
            def val = conf.get(it)
            if (val == null || val.toString() == '{}') {
                return false
            }
            return true
        }
        if (key) {
            return conf.get(key)
        }
        return null
    }

    private List<String> getAsStringList(def conf, String paramHumanName, String paramName = '???') {
        def raw = conf

        if (raw == null) {
            log.error("Invalid $paramHumanName filters configuration: '$raw'")
        } else if (raw instanceof Collection) {
            return raw.collect { it.toString() }
        } else if (raw instanceof String) {
            return raw.split(',').collect { it.trim() }
        } else {
            log.error("Invalid $paramHumanName filters configuration, invalid value type: '${raw.getClass()}'. Value should be defined as a Collection or String (comma separated)")
        }
        return null
    }
}
