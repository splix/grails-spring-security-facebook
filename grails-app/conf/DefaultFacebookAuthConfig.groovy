security {

	facebook {

        appId = "Invalid"
        language = "en_US"
        button.text = "Login with Facebook"

        domainClass = 'Facebook'

        //see http://developers.facebook.com/docs/authentication/permissions/
        permissions = ["email"]

        useAjax = true
        autoCheck = true

        jsconf = "fbSecurity"

        jsevent {
            login = 'onFacebookLogin'
            logout = 'onFacebookLogout'
        }

        registration {
            autocreate = true
            requiredAttributes = [:]
            createAccountUri = '/login/facebookCreateAccount'
            roleNames = ['ROLE_USER']
        }

        beans {
            filter = "facebookAuthFilter"
            provider = "facebookAuthProvider"
        }

    }
}