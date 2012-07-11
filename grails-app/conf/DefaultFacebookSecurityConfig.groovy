security {

	facebook {

        appId = "Invalid"
        secret = 'Invalid'
        apiKey = 'Invalid'

        domain {
            classname = 'FacebookUser'
            connectionPropertyName = "user"
        }

        useAjax = true
        autoCheck = true

        jsconf = "fbSecurity"

        taglib {
            language = "en_US"
            button {
                text = "Login with Facebook"
            }
            initfb = true
            //see http://developers.facebook.com/docs/authentication/permissions/
            permissions = ["email"]
        }

        autoCreate {
            active = true
            roleNames = ['ROLE_USER', 'ROLE_FACEBOOK']
        }

        filter {
            processUrl = "/j_spring_facebook_security_check"
            type = 'transparent' //transparent or cookieDirect
            position = 720 //see SecurityFilterPosition
            forceLoginParameter = 'j_spring_facebook_force'
        }

        beans {
        }

    }
}