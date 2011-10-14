package com.the6hours.grails.springsecurity.facebook

public interface FacebookUserDomain {
	
	String getSession();
	void setSession(String session);
	
	String getSecret();
	void setSecret(String secret);
	
	long getUid();
	void setUid(long uid)
}