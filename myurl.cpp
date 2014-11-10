/*
 *  myurl.cpp
 *  httptest
 *
 *  Created by apple on 11-5-23.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include "myurl.h"
#include <SystemConfiguration/SystemConfiguration.h>

void AddProxyAuthentication(CFHTTPAuthenticationRef authRef);
void AddProxyCredentials(CFHTTPAuthenticationRef authRef, CFMutableDictionaryRef credentials);
void DelProxyAuthentication(CFHTTPAuthenticationRef authRef);
CFHTTPAuthenticationRef FindProxyAuthenticationForRequest(CFHTTPMessageRef request);
CFMutableDictionaryRef FindProxyCredentials(CFHTTPAuthenticationRef authRef);
static void ReadStreamClientCallBack(CFReadStreamRef stream, CFStreamEventType type, void *clientCallBackInfo);
static void WriteStreamClientCallBack(CFWriteStreamRef stream, CFStreamEventType type, void *clientCallBackInfo);

static const CFOptionFlags kNetworkEvents =
    kCFStreamEventOpenCompleted | kCFStreamEventHasBytesAvailable | kCFStreamEventEndEncountered | kCFStreamEventErrorOccurred;

bool g_bHasProxy = false;
CFMutableArrayRef g_proxyAuthArray = NULL;
CFMutableDictionaryRef g_proxyCredDict = NULL;
const char* g_my_username = "test";
const char* g_my_password = "pass";
const char* g_proxy_domain = "mydomain";
enum {
	CF_PROXY_STATE_IDLE,
	CF_PROXY_STATE_WAITING,
	CF_PROXY_STATE_TRYING,
	CF_PROXY_STATE_DONE,
};

#if 0
#define MY_TRACE    printf
#else
#define MY_TRACE(fmt, ...) my_printf(MY_TRACE_LEVEL_INFO, fmt, ##__VA_ARGS__)
#endif

#define MY_TRACE_LEVEL_ERR 1
#define MY_TRACE_LEVEL_WARN 3
#define MY_TRACE_LEVEL_INFO 8

#include <asl.h>
aslclient log_client;
bool log_initialized = false;
void my_printf(int level, char* fmt, ...)
{
    va_list VAList;
    char szMsgBuf[2048] = {0};
    va_start(VAList, fmt);
    vsnprintf(szMsgBuf, sizeof(szMsgBuf)-1, fmt, VAList);
    
    if(!log_initialized) {
        log_initialized = true;
        log_client = asl_open("httptest", "httptest log Facility", ASL_OPT_STDERR);
    }
    
    switch(level)
    {
        case MY_TRACE_LEVEL_INFO:
            printf("%s\n", szMsgBuf);
            asl_log(log_client, NULL, ASL_LEVEL_EMERG, szMsgBuf);
            //WTP_INFOTRACE(szMsgBuf);
            break;
        case MY_TRACE_LEVEL_WARN:
            //WTP_WARNTRACE(szMsgBuf);
            break;
        case MY_TRACE_LEVEL_ERR:
            //WTP_ERRTRACE(szMsgBuf);
            break;
        default:
            //WTP_INFOTRACE(szMsgBuf);
            break;
    }
}

MY_Url_Object::MY_Url_Object()
{
	m_urlRef = NULL;
	m_messageRef = NULL;
	m_readStreamRef = NULL;
	
    m_content_length = 0;
    m_send_length = 0;
    m_reqBodyReadStream = NULL;
    m_reqBodyWriteStream = NULL;
    
	m_nProxyState = CF_PROXY_STATE_IDLE;
	m_shouldAutoredirect = true;
}

MY_Url_Object::~MY_Url_Object()
{
	if(m_urlRef)
	{
		CFRelease(m_urlRef);
		m_urlRef = NULL;
	}
    cleanup();
}

void MY_Url_Object::cleanup()
{
    if(m_messageRef)
    {
        CFRelease(m_messageRef);
        m_messageRef = NULL;
    }
    if(m_readStreamRef)
    {
        CFReadStreamSetClient(m_readStreamRef, NULL, NULL, NULL);
        CFReadStreamUnscheduleFromRunLoop(m_readStreamRef, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
        CFReadStreamClose(m_readStreamRef);
        CFRelease(m_readStreamRef);
        m_readStreamRef = NULL;
    }
    if(m_reqBodyReadStream)
    {
        CFReadStreamSetClient(m_reqBodyReadStream, NULL, NULL, NULL);
        CFReadStreamUnscheduleFromRunLoop(m_reqBodyReadStream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
        CFReadStreamClose(m_reqBodyReadStream);
        CFRelease(m_reqBodyReadStream);
        m_reqBodyReadStream = NULL;
    }
    if(m_reqBodyWriteStream)
    {
        CFWriteStreamSetClient(m_reqBodyWriteStream, NULL, NULL, NULL);
        CFWriteStreamUnscheduleFromRunLoop(m_reqBodyWriteStream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
        CFWriteStreamClose(m_reqBodyWriteStream);
        CFRelease(m_reqBodyWriteStream);
        m_reqBodyWriteStream = NULL;
    }
}

void MY_Url_Object::modifySSLSettings()
{
    if(NULL == m_readStreamRef) {
        return;
    }
    CFMutableDictionaryRef securityDictRef = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(securityDictRef) {
        CFDictionarySetValue(securityDictRef, kCFStreamSSLValidatesCertificateChain, kCFBooleanFalse);
        //CFDictionarySetValue(securityDictRef, kCFStreamSSLAllowsExpiredCertificates, kCFBooleanTrue);
        //CFDictionarySetValue(securityDictRef, kCFStreamSSLAllowsExpiredRoots, kCFBooleanTrue);
        //CFDictionarySetValue(securityDictRef, kCFStreamSSLAllowsAnyRoot, kCFBooleanTrue);
        CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertySSLSettings, securityDictRef);
        CFRelease(securityDictRef);
    }
}

int MY_Url_Object::get(const char* uri)
{
	MY_TRACE("MY_Url_Object::get, this=%lx, uri=%s", (unsigned long)this, uri);

	m_urlRef = CFURLCreateWithBytes(kCFAllocatorDefault, (const uint8_t*)uri, strlen(uri), CFStringGetSystemEncoding(), NULL);
	m_messageRef = CFHTTPMessageCreateRequest(kCFAllocatorDefault, CFSTR("GET"), m_urlRef, kCFHTTPVersion1_1);
    if(m_messageRef == NULL) {
        MY_TRACE("MY_Url_Object::get, error occur!");
        return -1;
    }
    
    //MY_TRACE("add header: WBX-Redirection-Address=http://eaccbmm20.webex.com:80");
    //CFHTTPMessageSetHeaderFieldValue(m_messageRef, CFSTR("WBX-Redirection-Address"), CFSTR("http://eaccbmm20.webex.com:80"));
	
	CFHTTPAuthenticationRef authentication = FindProxyAuthenticationForRequest(m_messageRef);
	if(authentication) {
		CFMutableDictionaryRef credentials = FindProxyCredentials(authentication);
		if(NULL == credentials || !CFHTTPMessageApplyCredentialDictionary(m_messageRef, authentication, credentials, NULL))
		{// Remove the authentication object
			DelProxyAuthentication(authentication);
		}
	}
	
    return doReadStream();
}

int MY_Url_Object::post(const char* uri, uint8_t* data, uint32_t len)
{
    MY_TRACE("MY_Url_Object::post, this=%lx, uri=%s, len=%d", (unsigned long)this, uri, len);
    
    m_urlRef = CFURLCreateWithBytes(kCFAllocatorDefault, (const uint8_t*)uri, strlen(uri), CFStringGetSystemEncoding(), NULL);
    m_messageRef = CFHTTPMessageCreateRequest(kCFAllocatorDefault, CFSTR("POST"), m_urlRef, kCFHTTPVersion1_1);
    if(m_messageRef == NULL) {
        MY_TRACE("MY_Url_Object::post, error occur!");
        return -1;
    }
    
    if(data && len > 0) {
        CFDataRef body = CFDataCreateWithBytesNoCopy(NULL, (uint8_t*)data, len, kCFAllocatorNull);
        CFHTTPMessageSetBody(m_messageRef, body);
    }
    
    CFHTTPAuthenticationRef authentication = FindProxyAuthenticationForRequest(m_messageRef);
    if(authentication) {
        CFMutableDictionaryRef credentials = FindProxyCredentials(authentication);
        if(NULL == credentials || !CFHTTPMessageApplyCredentialDictionary(m_messageRef, authentication, credentials, NULL))
        {// Remove the authentication object
            DelProxyAuthentication(authentication);
        }
    }
    
    return doReadStream();
}

int MY_Url_Object::streamPost(const char* uri, uint32_t content_length)
{
    int sockets[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    if(ret < 0) {
        return -1;
    }
    
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, sockets[0], &m_reqBodyReadStream, NULL);
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, sockets[1], NULL, &m_reqBodyWriteStream);
    if(!m_reqBodyReadStream || !m_reqBodyWriteStream) {
        cleanup();
        return -1;
    }
    
    CFReadStreamSetProperty(m_reqBodyReadStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    CFWriteStreamSetProperty(m_reqBodyWriteStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    
    CFStreamClientContext ctxt = {0, (void*)this, NULL, NULL, NULL};
    if(!CFWriteStreamSetClient(m_reqBodyWriteStream, kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred, WriteStreamClientCallBack, &ctxt)) {
        cleanup();
        return -1;
    }
    CFWriteStreamScheduleWithRunLoop(m_reqBodyWriteStream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    if(!CFWriteStreamOpen(m_reqBodyWriteStream)) {
        cleanup();
        return -1;
    }
    
    if(!CFReadStreamSetClient(m_reqBodyReadStream, kNetworkEvents, ReadStreamClientCallBack, &ctxt)) {
        cleanup();
        return -1;
    }
    CFReadStreamScheduleWithRunLoop(m_reqBodyReadStream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    if(!CFReadStreamOpen(m_reqBodyReadStream)) {
        cleanup();
        return -1;
    }
    
    m_urlRef = CFURLCreateWithBytes(kCFAllocatorDefault, (const uint8_t*)uri, strlen(uri), CFStringGetSystemEncoding(), NULL);
    m_messageRef = CFHTTPMessageCreateRequest(kCFAllocatorDefault, CFSTR("POST"), m_urlRef, kCFHTTPVersion1_1);
    if(m_messageRef == NULL) {
        MY_TRACE("MY_Url_Object::streamPost, error occur!");
        cleanup();
        return -1;
    }
    
    CFHTTPAuthenticationRef authentication = FindProxyAuthenticationForRequest(m_messageRef);
    if(authentication) {
        CFMutableDictionaryRef credentials = FindProxyCredentials(authentication);
        if(NULL == credentials || !CFHTTPMessageApplyCredentialDictionary(m_messageRef, authentication, credentials, NULL))
        {// Remove the authentication object
            DelProxyAuthentication(authentication);
        }
    }
    
    char szHeader[64];
    sprintf(szHeader, "%u", content_length);
    CFHTTPMessageSetHeaderFieldValue(m_messageRef, CFSTR("Content-Length"), __CFStringMakeConstantString(szHeader));
    m_content_length = content_length;
    
    m_readStreamRef = CFReadStreamCreateForStreamedHTTPRequest(kCFAllocatorDefault, m_messageRef, m_reqBodyReadStream);
    if(m_readStreamRef == NULL) {
        MY_TRACE("CFReadStreamCreateForStreamedHTTPRequest failed");
        cleanup();
        return -1;
    }
    if(m_shouldAutoredirect) {
        //CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertyHTTPShouldAutoredirect,kCFBooleanTrue);
    }
    
    CFDictionaryRef proxyDict = SCDynamicStoreCopyProxies(NULL);
    if(proxyDict) {
        CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertyHTTPProxy, proxyDict);
        CFRelease(proxyDict);
    }
    
    CFStringRef scheme = CFURLCopyScheme(m_urlRef);
    if(scheme && CFStringCompare(scheme, CFSTR("https"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        modifySSLSettings();
    }
    if(scheme) {
        CFRelease(scheme);
    }
    
    if (CFReadStreamSetClient( m_readStreamRef, kNetworkEvents, &ReadStreamClientCallBack, &ctxt) == false ) {
        CFStreamError error = CFReadStreamGetError(m_readStreamRef);
        MY_TRACE("CFReadStreamSetClient failed, error.domain=%ld, error.err=%d", error.domain, error.error);
        cleanup();
        return -1;
    }
    
    CFReadStreamScheduleWithRunLoop(m_readStreamRef, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    
    if (CFReadStreamOpen(m_readStreamRef) == false ) {
        CFStreamError error = CFReadStreamGetError(m_readStreamRef);
        MY_TRACE("CFReadStreamOpen failed, error.domain=%ld, error.err=%d", error.domain, error.error);
        cleanup();
        return -1;
    }
    MY_TRACE("reqReadStream=%lx, readStream=%lx", m_reqBodyReadStream, m_readStreamRef);
    return 0;
}

int MY_Url_Object::doReadStream()
{
    if(m_readStreamRef) {
        CFReadStreamSetClient(m_readStreamRef, NULL, NULL, NULL);
        CFReadStreamClose(m_readStreamRef);
        CFRelease(m_readStreamRef);
        m_readStreamRef = NULL;
    }
    m_readStreamRef = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, m_messageRef);
    if(m_readStreamRef == NULL) {
        MY_TRACE("CFReadStreamCreateForHTTPRequest failed");
        cleanup();
        return -1;
    }
    if(m_shouldAutoredirect) {
        CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertyHTTPShouldAutoredirect,kCFBooleanTrue);
    }
    
    CFDictionaryRef proxyDict = SCDynamicStoreCopyProxies(NULL);
    if(proxyDict) {
        CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertyHTTPProxy, proxyDict);
        CFRelease(proxyDict);
    }
    
    CFStringRef scheme = CFURLCopyScheme(m_urlRef);
    if(scheme && CFStringCompare(scheme, CFSTR("https"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        modifySSLSettings();
    }
    if(scheme) {
        CFRelease(scheme);
    }
    
    CFStreamClientContext ctxt = {0, this, NULL, NULL, NULL};
    if (CFReadStreamSetClient( m_readStreamRef, kNetworkEvents, &ReadStreamClientCallBack, &ctxt) == false ) {
        CFStreamError error = CFReadStreamGetError(m_readStreamRef);
        MY_TRACE("CFReadStreamSetClient failed, error.domain=%ld, error.err=%d", error.domain, error.error);
        cleanup();
        return -1;
    }
    
    CFReadStreamScheduleWithRunLoop(m_readStreamRef, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    
    if (CFReadStreamOpen(m_readStreamRef) == false ) {
        CFStreamError error = CFReadStreamGetError(m_readStreamRef);
        MY_TRACE("CFReadStreamOpen failed, error.domain=%ld, error.err=%d", error.domain, error.error);
        cleanup();
        return -1;
    }
    return 0;
}

int MY_Url_Object::sendBody(uint8_t* data, uint32_t len)
{
    if(!m_reqBodyWriteStream) {
        return 0;
    }
    if(!CFWriteStreamCanAcceptBytes(m_reqBodyWriteStream)) {
        return 0;
    }
    int ret = CFWriteStreamWrite(m_reqBodyWriteStream, data, len);
    if(ret > 0) {
        m_send_length += ret;
        if(m_send_length >= m_content_length)
        {// 03/02/2009, Folki+, don't close read stream. Sync from iphone team
            CFWriteStreamSetClient(m_reqBodyWriteStream, NULL, NULL, NULL);
            CFWriteStreamUnscheduleFromRunLoop(m_reqBodyWriteStream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
            CFWriteStreamClose(m_reqBodyWriteStream);
            CFRelease(m_reqBodyWriteStream);
            m_reqBodyWriteStream = NULL;
        }
    }
    return ret;
}

// return true means need proxy authentication
bool MY_Url_Object::tryHandleProxy()
{
	CFHTTPMessageRef responseHeader = NULL;
	responseHeader = (CFHTTPMessageRef)CFReadStreamCopyProperty(
																m_readStreamRef,
																kCFStreamPropertyHTTPResponseHeader
																);
	if(responseHeader)
	{
		//if (CFHTTPMessageIsHeaderComplete(responseHeader))
		{
			UInt32	statCode = CFHTTPMessageGetResponseStatusCode(responseHeader);
			if(statCode == 401 || statCode == 407)
			{
				g_bHasProxy = true;
				MY_TRACE("MY_Url_Object::tryHandleProxy, ACCOUNTS AND PASSWORD REQUIRED, this=%lx, code=%d", (unsigned long)this, statCode);
				CFHTTPAuthenticationRef authRef = FindProxyAuthenticationForRequest(m_messageRef);
				if(NULL == authRef)
				{
					authRef = CFHTTPAuthenticationCreateFromResponse(NULL, responseHeader);
					if(authRef)
					{
						AddProxyAuthentication(authRef);
						CFRelease(authRef); // retained by array
					}
					else
					{
						MY_TRACE("MY_Url_Object::tryHandleProxy, failed to create proxy authentication");
						CFRelease(responseHeader);
						return false;
					}
				}
				else
				{
					CFStreamError err;
					if(!CFHTTPAuthenticationIsValid(authRef, &err))
					{
						DelProxyAuthentication(authRef);
						if (err.domain == kCFStreamErrorDomainHTTP &&
							(err.error == kCFStreamErrorHTTPAuthenticationBadUserName ||
							 err.error == kCFStreamErrorHTTPAuthenticationBadPassword)) {
							CFRelease(responseHeader);
							// toss bad authentication and retry
							MY_TRACE("MY_Url_Object::tryHandleProxy, bad user name or password");
							return tryHandleProxy();
						}
						else
						{// error occur
							MY_TRACE("MY_Url_Object::tryHandleProxy, proxy error, err.domain=%ld, err.error=%d", err.domain, err.error);
							CFRelease(responseHeader);
							return false;
						}
					}
				}
				CFStringRef schemeRef = CFHTTPAuthenticationCopyMethod(authRef);
				MY_TRACE("MY_Url_Object::tryHandleProxy, scheme=%s", (CFStringGetCStringPtr(schemeRef, kCFStringEncodingASCII)));
                if(schemeRef && CFStringCompare(schemeRef, CFSTR("NTLM"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
					m_shouldAutoredirect = false;
                }
				CFRelease(schemeRef);

				CFMutableDictionaryRef credentials = FindProxyCredentials(authRef);
				if(NULL == credentials && CFHTTPAuthenticationRequiresUserNameAndPassword(authRef))
				{// try to get credentials from user
					MY_TRACE("MY_Url_Object::tryHandleProxy, need user name & password");
					credentials = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, 
						&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
					CFStringRef username = CFStringCreateWithCString(NULL, g_my_username, kCFStringEncodingASCII);
					CFDictionarySetValue(credentials, kCFHTTPAuthenticationUsername, username);
					CFRelease(username);
					CFStringRef password = CFStringCreateWithCString(NULL, g_my_password, kCFStringEncodingASCII);
					CFDictionarySetValue(credentials, kCFHTTPAuthenticationPassword, password);
					CFRelease(password);
					if(CFHTTPAuthenticationRequiresAccountDomain(authRef))
					{
						MY_TRACE("MY_Url_Object::tryHandleProxy, need domain");
						CFStringRef domain = CFStringCreateWithCString(NULL, g_proxy_domain, kCFStringEncodingASCII);
						CFDictionarySetValue(credentials, kCFHTTPAuthenticationAccountDomain, domain);
						CFRelease(domain);
					}
					AddProxyCredentials(authRef, credentials);
					CFRelease(credentials); // It's retained in the dictionary now
					resumeRequestWithCredentials(authRef, credentials);
					
					//m_nProxyState = CF_PROXY_STATE_WAITING;
				} else {// resume with credentials
					if(NULL == credentials) {
						credentials = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, 
							&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
						AddProxyCredentials(authRef, credentials);
						CFRelease(credentials); // It's retained in the dictionary now
					}
					resumeRequestWithCredentials(authRef, credentials);
				}
				CFRelease(responseHeader);
				return true;
			}
		}
		CFRelease(responseHeader);
	}
	
	return false;
}

bool MY_Url_Object::resumeRequestWithCredentials(CFHTTPAuthenticationRef authRef, CFDictionaryRef credentials)
{
	MY_TRACE("MY_Url_Object::resumeRequestWithCredentials, this=%lx", (unsigned long)this);

	if(m_messageRef == NULL) {
		MY_TRACE("MY_Url_Object::resumeRequestWithCredentials, m_MessageRef is NULL");
        m_nProxyState = CF_PROXY_STATE_IDLE;
        return false;
	}
	
	if(!CFHTTPMessageApplyCredentialDictionary(m_messageRef, authRef, credentials, NULL)) {
		MY_TRACE("MY_Url_Object::resumeRequestWithCredentials, CFHTTPMessageApplyCredentialDictionary failed");
	}
	
    if(doReadStream() == 0){
        m_nProxyState = CF_PROXY_STATE_TRYING;
        return true;
    } else {
        m_nProxyState = CF_PROXY_STATE_IDLE;
        return false;
    }
}

void MY_Url_Object::onConnect(int err)
{
    
}

void MY_Url_Object::onSend(int err)
{
    uint8_t body[1024];
    sendBody(body, m_content_length);
}

void MY_Url_Object::onReceive(int err)
{
	if(CF_PROXY_STATE_WAITING == m_nProxyState)
		return;
	if((CF_PROXY_STATE_IDLE == m_nProxyState || CF_PROXY_STATE_TRYING == m_nProxyState) && tryHandleProxy())
		return ;
	if(CF_PROXY_STATE_TRYING == m_nProxyState) {
		m_nProxyState = CF_PROXY_STATE_DONE;
		MY_TRACE("MY_Url_Object::onReceive, proxy done");
	}
	
    UInt8		buf[4096] = {0};
	Size		len = 0;
	len = CFReadStreamRead(m_readStreamRef, buf, sizeof(buf));
	if(len <= 0 && 0 == err)
	{
		MY_TRACE("MY_Url_Object::onReceive, error");
		if (m_readStreamRef != NULL) {
			CFReadStreamSetClient(m_readStreamRef, NULL, NULL, NULL);
			CFReadStreamClose(m_readStreamRef);
			CFRelease(m_readStreamRef);
			m_readStreamRef = NULL;
		}
	}
	else
	{
		MY_TRACE("MY_Url_Object::onReceive, len=%ld", len);
        MY_TRACE("%s\n", (char*) buf);
	}
}

void MY_Url_Object::onClose(int err)
{
	MY_TRACE("MY_Url_Object::onClose, err=%d", err);
}

static void ReadStreamClientCallBack(CFReadStreamRef stream, CFStreamEventType type, void *clientCallBackInfo)
{
	MY_Url_Object* urlObject = (MY_Url_Object*)clientCallBackInfo;
    if(NULL == urlObject) {
		return ;
    }
	switch (type)
	{
		case kCFStreamEventHasBytesAvailable:
			MY_TRACE("ReadStreamClientCallBack --- received data, obj=%lx", (long)urlObject);
			urlObject->onReceive(0);
			break;
		case kCFStreamEventEndEncountered:
			MY_TRACE("ReadStreamClientCallBack --- received data on finishing, obj=%lx", (long)urlObject);
			urlObject->onReceive(1);
			break;
		case kCFStreamEventErrorOccurred:
			MY_TRACE("ReadStreamClientCallBack --- error occurred, obj=%lx", (long)urlObject);
			urlObject->onClose(0);
			break;
		case kCFStreamEventOpenCompleted:	
			MY_TRACE("ReadStreamClientCallBack --- open complete, obj=%lx, stream=%lx", (long)urlObject, (long)stream);
            urlObject->onConnect(0);
			break;
		case kCFStreamEventCanAcceptBytes:				
			MY_TRACE("ReadStreamClientCallBack kCFStreamEventCanAcceptBytes, obj=%lx, stream=%lx", (long)urlObject, (long)stream);
			break;
		case kCFStreamEventNone:
			MY_TRACE("ReadStreamClientCallBack kCFStreamEventNone, obj=%lx", (long)urlObject);
			break;
		default:
			break;
	}
}

static void WriteStreamClientCallBack(CFWriteStreamRef stream, CFStreamEventType type, void *clientCallBackInfo)
{
    MY_Url_Object* urlObject = (MY_Url_Object*)clientCallBackInfo;
    if(NULL == urlObject) {
        return ;
    }
    
    if(type == kCFStreamEventCanAcceptBytes) {
        MY_TRACE("WriteStreamClientCallBack --- can send data, obj=%lx", (long)urlObject);
        urlObject->onSend(0);
    } else if(type == kCFStreamEventErrorOccurred) {
        MY_TRACE("WriteStreamClientCallBack --- error occurred, obj=%lx", (long)urlObject);
        urlObject->onClose(1);
    }
}

void DelProxyCredentials(CFHTTPAuthenticationRef authRef);
void AddProxyAuthentication(CFHTTPAuthenticationRef authRef)
{
    if(NULL == g_proxyAuthArray) {
		g_proxyAuthArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    }
	CFArrayAppendValue(g_proxyAuthArray, authRef);
}

void DelProxyAuthentication(CFHTTPAuthenticationRef authRef)
{
    if(NULL == g_proxyAuthArray) {
		return ;
    }
	// remove any matching credentials from the credentialDict
	CFIndex authIndex = CFArrayGetFirstIndexOfValue(g_proxyAuthArray, CFRangeMake(0, CFArrayGetCount(g_proxyAuthArray)), authRef);
	if (authIndex != kCFNotFound) {
		CFArrayRemoveValueAtIndex(g_proxyAuthArray, authIndex);
	}
    DelProxyCredentials(authRef);
}

void AddProxyCredentials(CFHTTPAuthenticationRef authRef, CFMutableDictionaryRef credentials)
{
    if(NULL == g_proxyCredDict) {
		g_proxyCredDict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
	CFDictionarySetValue(g_proxyCredDict, authRef, credentials);
}

void DelProxyCredentials(CFHTTPAuthenticationRef authRef)
{
    if(g_proxyCredDict) {
		CFDictionaryRemoveValue(g_proxyCredDict, authRef);
    }
}

CFHTTPAuthenticationRef FindProxyAuthenticationForRequest(CFHTTPMessageRef request)
{
    if(NULL == g_proxyAuthArray) {
		return NULL;
    }
	int i, c = CFArrayGetCount(g_proxyAuthArray);
	for (i = 0; i < c; i ++) {
		CFHTTPAuthenticationRef authRef = (CFHTTPAuthenticationRef)CFArrayGetValueAtIndex(g_proxyAuthArray, i);
		if (CFHTTPAuthenticationAppliesToRequest(authRef, request)) {
			return authRef;
		}
	}
	return NULL;
}

CFMutableDictionaryRef FindProxyCredentials(CFHTTPAuthenticationRef authRef)
{
    if(NULL == g_proxyCredDict) {
		return NULL;
    }
	return (CFMutableDictionaryRef)CFDictionaryGetValue(g_proxyCredDict, authRef);
}