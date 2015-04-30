/*
 *  myurl.cpp
 *  httptest
 *
 *  Created by Fengping Bao <jamol@live.com> on 11-5-23.
 *  Copyright 2011. All rights reserved.
 *
 */

#include "myurl.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <string>

void AddProxyAuthentication(CFHTTPAuthenticationRef authRef);
void AddProxyCredentials(CFHTTPAuthenticationRef authRef, CFMutableDictionaryRef credentials);
void DelProxyAuthentication(CFHTTPAuthenticationRef authRef);
CFHTTPAuthenticationRef FindProxyAuthenticationForRequest(CFHTTPMessageRef request);
CFMutableDictionaryRef FindProxyCredentials(CFHTTPAuthenticationRef authRef);
static void ReadStreamClientCallBack(CFReadStreamRef stream, CFStreamEventType type, void *clientCallBackInfo);
static void WriteStreamClientCallBack(CFWriteStreamRef stream, CFStreamEventType type, void *clientCallBackInfo);
const char* CertStatusFromOSStatus(OSStatus status) ;

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
void my_printf(int level, const char* fmt, ...)
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
            //asl_log(log_client, NULL, ASL_LEVEL_EMERG, szMsgBuf);
            break;
        case MY_TRACE_LEVEL_WARN:
            break;
        case MY_TRACE_LEVEL_ERR:
            break;
        default:
            break;
    }
}

MY_Url_Object::MY_Url_Object()
: m_urlRef(NULL)
, m_messageRef(NULL)
, m_readStreamRef(NULL)
, m_reqBodyReadStream(NULL)
, m_reqBodyWriteStream(NULL)
, m_content_length(0)
, m_send_length(0)
, m_nProxyState(CF_PROXY_STATE_IDLE)
, m_shouldAutoredirect(true)
, m_checkSSL(true)
{

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
    MY_TRACE("MY_Url_Object::streamPost, this=%lx, uri=%s, content_length=%u", (unsigned long)this, uri, content_length);
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
        //CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertyHTTPShouldAutoredirect, kCFBooleanTrue);
    }
    
    CFDictionaryRef proxyDict = SCDynamicStoreCopyProxies(NULL);
    if(proxyDict) {
        CFReadStreamSetProperty(m_readStreamRef, kCFStreamPropertyHTTPProxy, proxyDict);
        CFRelease(proxyDict);
    }
    
    CFStringRef scheme = CFURLCopyScheme(m_urlRef);
    if(scheme && CFStringCompare(scheme, CFSTR("https"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        //modifySSLSettings();
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
    MY_TRACE("MY_Url_Object::streamPost, reqReadStream=%lx, readStream=%lx", m_reqBodyReadStream, m_readStreamRef);
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
        //modifySSLSettings();
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
        {// don't close read stream
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
bool MY_Url_Object::tryHandleProxy(CFHTTPMessageRef responseHeader)
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
                        // toss bad authentication and retry
                        MY_TRACE("MY_Url_Object::tryHandleProxy, bad user name or password");
                        return tryHandleProxy(responseHeader);
                    }
                else
                {// error occur
                    MY_TRACE("MY_Url_Object::tryHandleProxy, proxy error, err.domain=%ld, err.error=%d", err.domain, err.error);
                    return false;
                }
            }
            MY_TRACE("MY_Url_Object::tryHandleProxy, find AuthenticationRef");
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
                MY_TRACE("MY_Url_Object::tryHandleProxy, create empty credentials");
                credentials = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, 
                                                        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                AddProxyCredentials(authRef, credentials);
                CFRelease(credentials); // It's retained in the dictionary now
            } else {
                MY_TRACE("MY_Url_Object::tryHandleProxy, find credentials");
            }
            resumeRequestWithCredentials(authRef, credentials);
        }
        return true;
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
    if(m_checkSSL) {
        m_checkSSL = false;
        checkSSLResult();
    }
    
	if(CF_PROXY_STATE_WAITING == m_nProxyState)
		return;
    if(CF_PROXY_STATE_IDLE == m_nProxyState || CF_PROXY_STATE_TRYING == m_nProxyState) {
        CFHTTPMessageRef responseHeader = NULL;
        responseHeader = (CFHTTPMessageRef)CFReadStreamCopyProperty(m_readStreamRef,
                                                                    kCFStreamPropertyHTTPResponseHeader
                                                                    );
        if(NULL == responseHeader || !CFHTTPMessageIsHeaderComplete(responseHeader)){
            if(responseHeader) CFRelease(responseHeader);
            return ;
        }
        bool ret = tryHandleProxy(responseHeader);
        CFRelease(responseHeader);
        if(ret) {
            return ;
        }
    }
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

static std::string GetErrorString(SecTrustRef secTrust)
{
    std::string errStr = "";
    // warning: sometimes it will stuck on SecTrustCopyProperties
    CFArrayRef arrayRef = SecTrustCopyProperties(secTrust);
    if(arrayRef && CFArrayGetCount(arrayRef) > 0) {
        CFDictionaryRef dictRef = (CFDictionaryRef)CFArrayGetValueAtIndex(arrayRef, 0);
        if(dictRef) {
            CFStringRef errRef = (CFStringRef)CFDictionaryGetValue(dictRef, kSecPropertyTypeError);
            if(errRef) {
                const char* cstr = CFStringGetCStringPtr(errRef, kCFStringEncodingASCII);
                if(cstr) {
                    errStr = cstr;
                }
                CFRelease(errRef);
            }
        }
        CFRelease(arrayRef);
    }
    return errStr;
}

void MY_Url_Object::checkSSLResult()
{
    OSStatus status;
    SSLContextRef sslContext = (SSLContextRef)CFReadStreamCopyProperty(m_readStreamRef, kCFStreamPropertySSLContext);
    if(sslContext) {
        SecTrustRef secTrust = NULL;
        status = SSLCopyPeerTrust (sslContext, &secTrust);
        if(secTrust) {
            CFRelease(secTrust);
        }
        CFRelease(sslContext);
    }
    SecTrustRef secTrust = (SecTrustRef)CFReadStreamCopyProperty(m_readStreamRef, kCFStreamPropertySSLPeerTrust);
    if(secTrust) {
        SecTrustResultType trustResult;
        status = SecTrustGetTrustResult(secTrust, &trustResult);
        printf("CheckSSLResult, SecTrustGetTrustResult status=%d, result=%d\n", status, trustResult);
        if(trustResult != kSecTrustResultUnspecified && trustResult != kSecTrustResultProceed) {
            OSStatus cssmResult;
            status = SecTrustGetCssmResultCode(secTrust, &cssmResult);
            printf("cert status: %s, result=%d\n", CertStatusFromOSStatus(cssmResult), trustResult);
            std::string errStr = GetErrorString(secTrust);
            printf("MY_Url_Object::checkSSLResult, errStr1=%s\n", errStr.c_str());
        } else {
            SecCertificateRef certs[10];
            CFIndex count = SecTrustGetCertificateCount(secTrust);
            for (CFIndex i = 0; i < count; i++)
            {
                SecCertificateRef certRef = SecTrustGetCertificateAtIndex(secTrust, i);
                certs[i] = certRef;
                CFStringRef certSummary = SecCertificateCopySubjectSummary(certRef);
                printf("checkSSLResult, summary=%s\n", CFStringGetCStringPtr(certSummary, kCFStringEncodingASCII));
                CFRelease(certSummary);
                //CFDataRef certData = SecCertificateCopyData(certRef);
            }
            CFArrayRef certArray = CFArrayCreate(NULL, (const void **)certs, count, NULL);
            SecPolicyRef secPolicy = SecPolicyCreateBasicX509();
            //SecPolicyRef secPolicy = SecPolicyCreateSSL(false, CFSTR("revoked.grc.com"));
            SecTrustRef tmpTrust;
            OSStatus status = SecTrustCreateWithCertificates(certArray, secPolicy, &tmpTrust);
            status = SecTrustEvaluate(tmpTrust, &trustResult);
            printf("CheckSSLResult, SecTrustEvaluate status=%d, result=%d\n", status, trustResult);
            if (trustResult != kSecTrustResultUnspecified && trustResult != kSecTrustResultProceed) {
                OSStatus cssmResult;
                status = SecTrustGetCssmResultCode(tmpTrust, &cssmResult);
                printf("cert is not OK, cert status: %s\n", CertStatusFromOSStatus(cssmResult));
                std::string errStr = GetErrorString(tmpTrust);
                printf("MY_Url_Object::checkSSLResult, errStr2=%s\n", errStr.c_str());
            } else {
                printf("cert is OK\n");
            }
            CFRelease(tmpTrust);
            CFRelease(secPolicy);
            CFRelease(certArray);
        }
        
        CFRelease(secTrust);
    }
}

void MY_Url_Object::onClose(int err)
{
    CFStreamError strErr = CFReadStreamGetError(m_readStreamRef);
    MY_TRACE("MY_Url_Object::onClose, error=%d, domain=%d", strErr.error, strErr.domain);
    /*CFDataRef ref = (CFDataRef)CFReadStreamCopyProperty(m_readStreamRef, kCFStreamPropertySSLContext);
    SSLContextRef contextRef;
    CFDataGetBytes(ref, CFRangeMake(0, sizeof(SSLContextRef)), (UInt8 *)&contextRef);*/
    if(strErr.domain == kCFStreamErrorDomainSSL) {
        checkSSLResult();
    }
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
			urlObject->onClose(1);
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
		g_proxyAuthArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
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
		g_proxyCredDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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

const char* CertStatusFromOSStatus(OSStatus status) {
    switch (status) {
        case noErr:
            return "CERT_STATUS_OK";
        case CSSMERR_TP_INVALID_ANCHOR_CERT:
        case CSSMERR_TP_NOT_TRUSTED:
        case CSSMERR_TP_INVALID_CERT_AUTHORITY:
            return "CERT_STATUS_AUTHORITY_INVALID";
        case CSSMERR_TP_CERT_EXPIRED:
        case CSSMERR_TP_CERT_NOT_VALID_YET:
            // "Expired" and "not yet valid" collapse into a single status.
            return "CERT_STATUS_DATE_INVALID";
        case CSSMERR_TP_CERT_REVOKED:
        case CSSMERR_TP_CERT_SUSPENDED:
            return "CERT_STATUS_REVOKED";
        case CSSMERR_APPLETP_HOSTNAME_MISMATCH:
            return "CERT_STATUS_COMMON_NAME_INVALID";
        case CSSMERR_APPLETP_CRL_NOT_FOUND:
        case CSSMERR_APPLETP_OCSP_UNAVAILABLE:
        case CSSMERR_APPLETP_INCOMPLETE_REVOCATION_CHECK:
            return "CERT_STATUS_NO_REVOCATION_MECHANISM";
        case CSSMERR_APPLETP_CRL_EXPIRED:
        case CSSMERR_APPLETP_CRL_NOT_VALID_YET:
        case CSSMERR_APPLETP_CRL_SERVER_DOWN:
        case CSSMERR_APPLETP_CRL_NOT_TRUSTED:
        case CSSMERR_APPLETP_CRL_INVALID_ANCHOR_CERT:
        case CSSMERR_APPLETP_CRL_POLICY_FAIL:
        case CSSMERR_APPLETP_OCSP_BAD_RESPONSE:
        case CSSMERR_APPLETP_OCSP_BAD_REQUEST:
        case CSSMERR_APPLETP_OCSP_STATUS_UNRECOGNIZED:
        case CSSMERR_APPLETP_NETWORK_FAILURE:
        case CSSMERR_APPLETP_OCSP_NOT_TRUSTED:
        case CSSMERR_APPLETP_OCSP_INVALID_ANCHOR_CERT:
        case CSSMERR_APPLETP_OCSP_SIG_ERROR:
        case CSSMERR_APPLETP_OCSP_NO_SIGNER:
        case CSSMERR_APPLETP_OCSP_RESP_MALFORMED_REQ:
        case CSSMERR_APPLETP_OCSP_RESP_INTERNAL_ERR:
        case CSSMERR_APPLETP_OCSP_RESP_TRY_LATER:
        case CSSMERR_APPLETP_OCSP_RESP_SIG_REQUIRED:
        case CSSMERR_APPLETP_OCSP_RESP_UNAUTHORIZED:
        case CSSMERR_APPLETP_OCSP_NONCE_MISMATCH:
            // We asked for a revocation check, but didn't get it.
            return "CERT_STATUS_UNABLE_TO_CHECK_REVOCATION";
        case CSSMERR_APPLETP_SSL_BAD_EXT_KEY_USE:
            // TODO(wtc): Should we add CERT_STATUS_WRONG_USAGE?
            return "CERT_STATUS_INVALID";
        case CSSMERR_APPLETP_CRL_BAD_URI:
        case CSSMERR_APPLETP_IDP_FAIL:
            return "CERT_STATUS_INVALID";
        case CSSMERR_CSP_UNSUPPORTED_KEY_SIZE:
            // Mapping UNSUPPORTED_KEY_SIZE to CERT_STATUS_WEAK_KEY is not strictly
            // accurate, as the error may have been returned due to a key size
            // that exceeded the maximum supported. However, within
            // CertVerifyProcMac::VerifyInternal(), this code should only be
            // encountered as a certificate status code, and only when the key size
            // is smaller than the minimum required (1024 bits).
            return "CERT_STATUS_WEAK_KEY";
        default: {
            // Failure was due to something Chromium doesn't define a
            // specific status for (such as basic constraints violation, or
            // unknown critical extension)
            // "Unknown error mapped to CERT_STATUS_INVALID";
            return "CERT_STATUS_INVALID";
        }
    }
}
