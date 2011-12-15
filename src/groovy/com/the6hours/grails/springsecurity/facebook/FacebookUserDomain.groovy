package com.the6hours.grails.springsecurity.facebook

public interface FacebookUserDomain {
	
	String getAccessToken();
	void setAccessToken(String accessToken);
	
	long getUid();
	void setUid(long uid)
}