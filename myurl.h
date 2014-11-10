/*
 *  myurl.h
 *  httptest
 *
 *  Created by Fengping Bao <jamol@live.com> on 11-5-23.
 *  Copyright 2011. All rights reserved.
 *
 */
#ifndef __MYURL_H__
#define __MYURL_H__
#include <Coreservices/CoreServices.h>

class MY_Url_Object{
public:
	MY_Url_Object();
	~MY_Url_Object();
	
	int get(const char* uri);
    int post(const char* uri, uint8_t* data, uint32_t len);
    int streamPost(const char* uri, uint32_t content_length);
    int sendBody(uint8_t* data, uint32_t len);
	
    void onConnect(int err);
    void onSend(int err);
	void onReceive(int err);
	void onClose(int err);
	
private:
	bool tryHandleProxy();
	bool resumeRequestWithCredentials(CFHTTPAuthenticationRef authRef, CFDictionaryRef credentials);
    void modifySSLSettings();
    int doReadStream();
    void cleanup();
	
private:
	CFURLRef            m_urlRef;
	CFHTTPMessageRef    m_messageRef;
	CFReadStreamRef     m_readStreamRef;
    
    uint32_t            m_content_length;
    uint32_t            m_send_length;
    CFReadStreamRef     m_reqBodyReadStream;
    CFWriteStreamRef    m_reqBodyWriteStream;
	
	int                 m_nProxyState;
	bool                m_shouldAutoredirect;
};

#endif
