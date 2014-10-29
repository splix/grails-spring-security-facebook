import grails.util.GrailsNameUtils
import groovy.text.SimpleTemplateEngine

includeTargets << grailsScript("_GrailsInit")
includeTargets << grailsScript('_GrailsBootstrap')

overwriteAll = false
templateAttributes = [:]
templateDir = "$springSecurityFacebookPluginDir/src/templates"
resourceDir = "$springSecurityFacebookPluginDir/src/resources"
pluginAppDir = "$springSecurityFacebookPluginDir/grails-app"
appDir = "$basedir/grails-app"
webDir = "$basedir/web-app"
templateEngine = new SimpleTemplateEngine()
pluginConfig = [:]
beans = []

target(s2InitFacebook: 'Initializes Twitter artifacts for the Spring Security Facebook plugin') {
    depends(checkVersion, configureProxy, packageApp, classpath)

    def configFile = new File(springSecurityFacebookPluginDir, "grails-app/conf/DefaultFacebookSecurityConfig.groovy")
    if (configFile.exists()) {
        def conf = new ConfigSlurper().parse(configFile.text)

        pluginConfig = conf.security.facebook
        if (conf.verbose) {
            println "Creating app based on configuration:"
            pluginConfig.each { name, config -> println "$name = ${config.flatten()}" }
        }
    } else {
        ant.echo message: "ERROR $configFile.path not found"
    }

    configure()
    copyData()
    fillConfig()
    if (!beans.empty) {
        addBeans(beans)
    }
}

private void fillConfig() {
    def config = new ConfigObject()

    config.domain.classname = pluginConfig.domain.classname

    String code

    code = "facebook.appId"
    ant.input(message: "Enter your Facebook App ID", addproperty: code)
    config.appId = ant.antProject.properties[code]

    code = "facebook.secret"
    ant.input(message: "Enter your Facebook App Secret", addproperty: code)
    config.secret = ant.antProject.properties[code]

    def configFile = new File(appDir, 'conf/Config.groovy')
    if (!configFile.exists()) {
        return
    }

    configFile.withWriterAppend {
        it.writeLine "\n"
        config.flatten().each { key, value ->
            it.writeLine "grails.plugin.springsecurity.facebook.$key='$value'"
        }
    }
}

private void configure() {

    def SpringSecurityUtils = classLoader.loadClass('grails.plugin.springsecurity.SpringSecurityUtils')
    def conf = SpringSecurityUtils.securityConfig

    String userClassFullName = conf.userLookup.userDomainClassName
    def userDomain = splitClassName(userClassFullName)

    templateAttributes = [
            packageDeclaration: '',
            userClassFullName: userClassFullName,
            userPackage: userDomain[0],
            userClassName: userDomain[1]
    ]

    //templateAttributes.entrySet().each {
    //    println "$it.key = $it.value"
    //}
}

private void copyData() {

    ant.input(message: "Do you already have FacebookUser domain? 'N' - if not, it will be created (Y/N):",
              addproperty: 'create.facebookdomain',
              defaultvalue: 'N')

    String createDomain = ant.antProject.properties['create.facebookdomain'].toLowerCase()
    if (createDomain == 'n') {
        ant.input(message: "Enter the name of the FacebookUser domain class to create",
                  addproperty: 'facebookdomain',
                  defaultvalue: 'FacebookUser')

        templateAttributes['domainClassFullName'] = ant.antProject.properties['facebookdomain']
        def dbUserDomain = splitClassName(templateAttributes['domainClassFullName'])
        templateAttributes['domainPackage'] = dbUserDomain[0]
        templateAttributes['domainPackageDeclaration'] = ''
        if (templateAttributes['domainPackage']) {
            templateAttributes['domainPackageDeclaration'] = "package $templateAttributes.domainPackage"
        }
        templateAttributes['domainClassName'] = dbUserDomain[1]
        String domainDir = packageToDir(templateAttributes['domainPackage'])
        if (domainDir) {
            domainDir += '/'
        }

        generateFile "$templateDir/FacebookUser.groovy.template",
                     "$basedir/grails-app/domain/${domainDir}${templateAttributes.domainClassName}.groovy"
        pluginConfig.domain.classname = templateAttributes['domainClassFullName']
    } else if (createDomain == 'y') {
        ant.input(message: "Existing domain name:",
                  addproperty: 'create.facebookdomainname',
                  defaultvalue: pluginConfig.domain.classname)

        templateAttributes['domainClassFullName'] = ant.antProject.properties['create.facebookdomainname']
        def dbUserDomain = splitClassName(templateAttributes['domainClassFullName'])
        templateAttributes['domainPackage'] = dbUserDomain[0]
        templateAttributes['domainClassName'] = dbUserDomain[1]

        pluginConfig.domain.classname = templateAttributes['domainClassFullName']
    } else {
        ant.echo(message: "Skip FacebookUser domain configuration")
    }
}

generateDao = {
    generateFile "$templateDir/FacebookAuthDaoImpl.groovy.template",
                 "$basedir/src/groovy/${templateAttributes.daoClassName}.groovy"
    ant.echo message: ""
    ant.echo message: "I've added `$appDir/src/groovy/${templateAttributes.daoClassName}.groovy` file"
    ant.echo message: "You need to implement all methods there, to start using Facebook Auth"
    ant.echo message: ""

    beans << generateBeanStr(templateAttributes['bean.dao'], templateAttributes['daoClassName'], [:])
}

packageToDir = { String packageName ->
    packageName ? packageName.replaceAll('\\.', '/') + '/' : ''
}

okToWrite = { String dest ->

    def file = new File(dest)
    if (overwriteAll || !file.exists()) {
        return true
    }

    String propertyName = "file.overwrite.$file.name"
    ant.input(addProperty: propertyName, message: "$dest exists, ok to overwrite?",
              validargs: 'y,n,a', defaultvalue: 'y')

    if (ant.antProject.properties."$propertyName" == 'n') {
        return false
    }

    if (ant.antProject.properties."$propertyName" == 'a') {
        overwriteAll = true
    }

    true
}

generateFile = { String templatePath, String outputPath ->
    if (!okToWrite(outputPath)) {
        return
    }

    File templateFile = new File(templatePath)
    if (!templateFile.exists()) {
        ant.echo message: "\nERROR: $templatePath doesn't exist"
        return
    }

    File outFile = new File(outputPath)

    // in case it's in a package, create dirs
    ant.mkdir dir: outFile.parentFile

    outFile.withWriter { writer ->
        templateEngine.createTemplate(templateFile.text).make(templateAttributes).writeTo(writer)
    }

    ant.echo message: "generated $outFile.absolutePath"
}

splitClassName = { String fullName ->

    int index = fullName.lastIndexOf('.')
    String packageName = ''
    String className = ''
    if (index > -1) {
        packageName = fullName[0..index-1]
        className = fullName[index+1..-1]
    }
    else {
        packageName = ''
        className = fullName
    }

    [packageName, className]
}

checkValue = { String value, String attributeName ->
    if (!value || value == '{}') {
        ant.echo message: "\nERROR: Cannot generate; $attributeName set as $value"
        System.exit 1
    }
}

copyFile = { String from, String to ->
    if (!okToWrite(to)) {
        return
    }

    ant.copy file: from, tofile: to, overwrite: true
}

private String generateBeanStr(String name, String className, Map params) {
    StringBuilder bean = new StringBuilder("\t$name($className) {\n")
    params.each { key, value -> bean.append"\t\t$key = $value\n" }
    bean.append "\t}\n"
    bean
}

private void cantAddBeans(List<String> beans) {
    ant.echo message: "ERROR: Can't add new beans into your Spring context."
    ant.echo message: "ERROR: Please add following lines into your Spring config (in most cases it's `spring/resources.groovy`):\n\n${beans.collect { it + '\n'}}\n"
}

private void addBeans(List<String> beans) {
    def current = new File(appDir, "conf/spring/resources.groovy")
    if (current.exists()) {
        String content = current.text.trim()
        if (current.renameTo("$appDir/conf/spring/resources.groovy.bak")) {
            ant.echo message: "Made a backup copy of your `spring/resources.groovy` as `spring/resources.groovy.bak`"
        } else {
            cantAddBeans(beans)
            return
        }
        if (content.endsWith('}')) {
            current = new File(appDir, "conf/spring/resources.groovy")
            if (current.createNewFile()) {
                current.append(content.substring(0, content.length() - 2))
                current.append('\n')
            }
        } else {
            cantAddBeans(beans)
            return
        }
    } else {
        if (current.createNewFile()) {
            current.append("beans = {\n\n")
        } else {
            cantAddBeans(beans)
            return
        }
    }

    beans.each {
        current.append(it)
        current.append('\n')
    }
    current.append('}')
}

setDefaultTarget 's2InitFacebook'
