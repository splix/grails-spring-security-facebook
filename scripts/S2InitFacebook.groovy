import grails.util.GrailsNameUtils

//includeTargets << new File("$springSecurityFacebookPluginDir/scripts/_OpenIdCommon.groovy")

target(s2InitFacebook: 'Initializes artifacts for the Spring Security Facebook plugin') {
	depends(checkVersion, configureProxy, packageApp, classpath)

    def SpringSecurityUtils = classLoader.loadClass(
	       'org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils')

    String prefix = "grails.plugins.springsecurity.facebook"

    String appId = ""
    checkValue appId, "0"

    String secret = ""
    checkValue secret, ""

    def configFile = new File(appDir, 'conf/Config.groovy')
    if (configFile.exists()) {
        configFile.withWriterAppend {
            it.writeLine "${prefix}.appId = $appId"
            it.writeLine "${prefix}.secret = $secret"
        }
    }
}

setDefaultTarget 's2InitFacebook'