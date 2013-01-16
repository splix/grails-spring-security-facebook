package com.the6hours.grails.springsecurity.facebook

/**
 * 
 * @author Igor Artamonov (http://igorartamonov.com)
 * @since 22.05.12
 */
class FacebookAccessToken implements Serializable {

  String accessToken
  Date expireAt

  String toString() {
      StringBuilder buf = new StringBuilder()
      buf.append('Access token: ').append(accessToken)
      buf.append(', expires at ').append(expireAt)
      return buf.toString()
  }

}
