#import <AppKit/AppKit.h>
#import <DeviceCheck/DeviceCheck.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>

// Thread-local error storage — avoids char** pointer-to-pointer FFI complexity.
static __thread char* dc_last_error_str = NULL;

static void dc_set_error(NSString* msg) {
  free(dc_last_error_str);
  dc_last_error_str = strdup([msg UTF8String]);
}

const char* dc_last_error(void) {
  return dc_last_error_str;
}

int dc_is_supported(void) {
  return [DCAppAttestService.sharedService isSupported] ? 1 : 0;
}

char* dc_generate_key(void) {
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block NSString* resultKeyId = nil;
  __block NSError* resultError = nil;

  [DCAppAttestService.sharedService
      generateKeyWithCompletionHandler:^(NSString* keyId, NSError* err) {
        resultKeyId = keyId;
        resultError = err;
        dispatch_semaphore_signal(sem);
      }];

  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

  if (resultError) {
    dc_set_error([resultError localizedDescription]);
    return NULL;
  }

  return strdup([resultKeyId UTF8String]);
}

uint8_t* dc_attest_key(const char* key_id, const uint8_t* client_data_hash,
                       size_t hash_len, size_t* out_len) {
  NSString* keyStr = [NSString stringWithUTF8String:key_id];
  NSData* hashData = [NSData dataWithBytes:client_data_hash length:hash_len];

  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block NSData* resultData = nil;
  __block NSError* resultError = nil;

  [DCAppAttestService.sharedService
      attestKey:keyStr
      clientDataHash:hashData
      completionHandler:^(NSData* attestation, NSError* err) {
        resultData = attestation;
        resultError = err;
        dispatch_semaphore_signal(sem);
      }];

  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

  if (resultError) {
    dc_set_error([resultError localizedDescription]);
    if (out_len) *out_len = 0;
    return NULL;
  }

  size_t len = [resultData length];
  uint8_t* buf = malloc(len);
  memcpy(buf, [resultData bytes], len);
  if (out_len) *out_len = len;
  return buf;
}

uint8_t* dc_generate_assertion(const char* key_id,
                               const uint8_t* client_data_hash,
                               size_t hash_len, size_t* out_len) {
  NSString* keyStr = [NSString stringWithUTF8String:key_id];
  NSData* hashData = [NSData dataWithBytes:client_data_hash length:hash_len];

  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block NSData* resultData = nil;
  __block NSError* resultError = nil;

  [DCAppAttestService.sharedService
      generateAssertion:keyStr
      clientDataHash:hashData
      completionHandler:^(NSData* assertion, NSError* err) {
        resultData = assertion;
        resultError = err;
        dispatch_semaphore_signal(sem);
      }];

  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

  if (resultError) {
    dc_set_error([resultError localizedDescription]);
    if (out_len) *out_len = 0;
    return NULL;
  }

  size_t len = [resultData length];
  uint8_t* buf = malloc(len);
  memcpy(buf, [resultData bytes], len);
  if (out_len) *out_len = len;
  return buf;
}

void dc_free_string(char* str) {
  free(str);
}

void dc_free_buffer(uint8_t* buf) {
  free(buf);
}

// ============================================================
// Custom URL scheme handler (pdrattest://)
// ============================================================

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
  dispatch_async(dispatch_get_main_queue(), ^{
    url_delegate = [[URLSchemeDelegate alloc] init];
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

// ============================================================
// Keychain storage (Secure Enclave-backed on Apple Silicon)
// ============================================================

static NSString* const KC_SERVICE = @"com.publicdomainrelay.macos-app-attest";

int keychain_save(const char* account, const uint8_t* data, size_t len) {
  NSString* acct = [NSString stringWithUTF8String:account];
  NSData* val = [NSData dataWithBytes:data length:len];

  NSDictionary* query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: KC_SERVICE,
    (__bridge id)kSecAttrAccount: acct,
  };
  SecItemDelete((__bridge CFDictionaryRef)query);

  NSDictionary* attrs = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: KC_SERVICE,
    (__bridge id)kSecAttrAccount: acct,
    (__bridge id)kSecValueData: val,
    (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
  };
  OSStatus st = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
  return st == errSecSuccess ? 1 : 0;
}

uint8_t* keychain_load(const char* account, size_t* out_len) {
  NSString* acct = [NSString stringWithUTF8String:account];
  NSDictionary* query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: KC_SERVICE,
    (__bridge id)kSecAttrAccount: acct,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
  };
  CFDataRef result = NULL;
  OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&result);
  if (st != errSecSuccess || !result) { if (out_len) *out_len = 0; return NULL; }
  NSData* data = (__bridge_transfer NSData*)result;
  size_t len = [data length];
  uint8_t* buf = malloc(len);
  memcpy(buf, [data bytes], len);
  if (out_len) *out_len = len;
  return buf;
}

// Same as keychain_load but returns a null-terminated C string, no size_t*
// out-param. JS side reads via readCStr → no pointer-arithmetic or buffer-
// lifecycle issues. Caller frees with dc_free_string.
char* keychain_load_str(const char* account) {
  NSString* acct = [NSString stringWithUTF8String:account];
  NSDictionary* query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: KC_SERVICE,
    (__bridge id)kSecAttrAccount: acct,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
  };
  CFDataRef result = NULL;
  OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&result);
  if (st != errSecSuccess || !result) return NULL;
  NSData* data = (__bridge_transfer NSData*)result;
  size_t len = [data length];
  char* buf = malloc(len + 1);
  memcpy(buf, [data bytes], len);
  buf[len] = '\0';
  return buf;
}

int keychain_delete(const char* account) {
  NSString* acct = [NSString stringWithUTF8String:account];
  NSDictionary* query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: KC_SERVICE,
    (__bridge id)kSecAttrAccount: acct,
  };
  OSStatus st = SecItemDelete((__bridge CFDictionaryRef)query);
  return st == errSecSuccess ? 1 : 0;
}
