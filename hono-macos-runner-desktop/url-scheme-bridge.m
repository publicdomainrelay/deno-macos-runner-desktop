#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

// Minimal native bridge: registers a handler for kAEGetURL so a custom
// URL scheme launch (OAuth callback) can be polled from Deno via FFI.
// No DeviceCheck / App Attest — that entitlement surface was removed
// project-wide in favor of software device keys (device-key-webcrypto).

static char* url_pending = NULL;

@interface URLSchemeDelegate : NSObject
- (void)handleGetURLEvent:(NSAppleEventDescriptor*)event withReplyEvent:(NSAppleEventDescriptor*)reply;
@end

@implementation URLSchemeDelegate
- (void)handleGetURLEvent:(NSAppleEventDescriptor*)event withReplyEvent:(NSAppleEventDescriptor*)reply {
  NSString* urlStr = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
  if (!urlStr) return;
  @synchronized(self) {
    free(url_pending);
    url_pending = strdup([urlStr UTF8String]);
  }
}
@end

static URLSchemeDelegate* url_delegate = nil;

void url_register_handler(void) {
  url_delegate = [[URLSchemeDelegate alloc] init];
  dispatch_async(dispatch_get_main_queue(), ^{
    [[NSAppleEventManager sharedAppleEventManager]
        setEventHandler:url_delegate
        andSelector:@selector(handleGetURLEvent:withReplyEvent:)
        forEventClass:kInternetEventClass
        andEventID:kAEGetURL];
  });
}

const char* url_scheme_pending(void) {
  char* result = NULL;
  @synchronized(url_delegate) {
    if (url_pending) {
      result = strdup(url_pending);
      free(url_pending);
      url_pending = NULL;
    }
  }
  return result;
}

void url_bridge_free_string(char* str) {
  free(str);
}
