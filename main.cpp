#include <iostream>
#include "myurl.h"
#include <Coreservices/CoreServices.h>

int main (int argc, char * const argv[]) {
    const char* uri3 = "https://revoked.grc.com";
	MY_Url_Object urlObject1, urlObject2;
	//urlObject1.get(uri);
    uint8_t data[] = {1, 2, 3, 4, 5, 6};
    //urlObject1.post(uri3, data, sizeof(data)/sizeof(data[0]));
    //urlObject1.streamPost(uri3, 50);
	urlObject2.get(uri3);
	CFRunLoopRun();
	printf("main exit\n");
	return 0;
}

