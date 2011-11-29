security {

	facebook {

        appId = "Invalid"
        secret = 'Invalid'
        apiKey = 'Invalid'

        language = "en_US"
        button.text = "Login with Facebook"

        domain {
            classname = 'FacebookUser'
            connectionPropertyName = "user"
        }

        //see http://developers.facebook.com/docs/authentication/permissions/
        permissions = ["email"]

        useAjax = true
        autoCheck = true

        jsconf = "fbSecurity"

        jsevent {
            login = 'onFacebookLogin'
            logout = 'onFacebookLogout'
        }

        autoCreate {
            active = true
            roleNames = ['ROLE_USER', 'ROLE_FACEBOOK']
        }

        filter {
            processUrl = "/j_spring_facebook_security_check"
            position = 720 //see SecurityFilterPosition
        }

        beans {
        }

    }
}