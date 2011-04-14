package org.codehaus.groovy.grails.plugins.springsecurity.facebook

public interface FacebookUser {
	
	String getSession();
	void setSession(String session);
	
	String getSecret();
	void setSecret(String secret);
	
	long getUid();
	void setUid(long uid)
}