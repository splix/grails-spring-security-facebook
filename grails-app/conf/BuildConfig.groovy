grails.project.class.dir = 'target/classes'
grails.project.test.class.dir = 'target/test-classes'
grails.project.test.reports.dir	= 'target/test-reports'

grails.release.scm.enabled=false
grails.project.repos.default = "grailsCentral"

grails.project.dependency.resolver = "maven"
grails.project.dependency.resolution = {

    inherits('global') {
        //excludes 'commons-codec' // Grails ships with 1.3, need 1.4
    }

    log 'warn'

    repositories {
        grailsPlugins()
        grailsHome()
        grailsCentral()
        mavenCentral()
    }

    plugins {
//        provided ':webxml:1.4.1'

        compile ':spring-security-core:2.0-RC4'

        build ':release:2.2.1', ':rest-client-builder:1.0.3', {
            export = false
        }

        test ":spock:0.7"
    }
}
