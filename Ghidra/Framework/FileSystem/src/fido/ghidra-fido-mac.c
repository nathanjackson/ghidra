/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "ghidra-fido-json.h"

#import <AppKit/AppKit.h>
#import <AuthenticationServices/AuthenticationServices.h>
#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *dup_mem(const void *src, size_t len) {
	if (!src || len == 0) {
		return NULL;
	}
	uint8_t *p = (uint8_t *)malloc(len);
	if (p) {
		memcpy(p, src, len);
	}
	return p;
}

static void set_err(char *err, size_t errlen, const char *msg) {
	if (err && errlen) {
		snprintf(err, errlen, "%s", msg ? msg : "FIDO helper failed");
	}
}

@interface GhidraFidoDelegate : NSObject <ASAuthorizationControllerDelegate,
	ASAuthorizationControllerPresentationContextProviding>
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, copy) NSString *errorMessage;
@property (nonatomic, assign) BOOL create;
@property (nonatomic, assign) BOOL done;
@property (nonatomic, assign) fido_response *resp;
@end

@implementation GhidraFidoDelegate

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:
	(ASAuthorizationController *)controller {
	return self.window;
}

- (void)copyData:(NSData *)data into:(uint8_t **)dst length:(size_t *)len {
	if (!data) {
		*dst = NULL;
		*len = 0;
		return;
	}
	*len = data.length;
	*dst = dup_mem(data.bytes, data.length);
}

- (void)authorizationController:(ASAuthorizationController *)controller
	didCompleteWithAuthorization:(ASAuthorization *)authorization {
	id cred = authorization.credential;
	if (self.create &&
		[cred isKindOfClass:[ASAuthorizationSecurityKeyPublicKeyCredentialRegistration class]]) {
		ASAuthorizationSecurityKeyPublicKeyCredentialRegistration *reg = cred;
		[self copyData:reg.credentialID into:&self.resp->credential_id
			length:&self.resp->credential_id_len];
		[self copyData:reg.rawClientDataJSON into:&self.resp->client_data_json
			length:&self.resp->client_data_json_len];
		[self copyData:reg.rawAttestationObject into:&self.resp->attestation_object
			length:&self.resp->attestation_object_len];
	}
	else if (!self.create &&
		[cred isKindOfClass:[ASAuthorizationSecurityKeyPublicKeyCredentialAssertion class]]) {
		ASAuthorizationSecurityKeyPublicKeyCredentialAssertion *assertion = cred;
		[self copyData:assertion.credentialID into:&self.resp->credential_id
			length:&self.resp->credential_id_len];
		[self copyData:assertion.rawAuthenticatorData into:&self.resp->authenticator_data
			length:&self.resp->authenticator_data_len];
		[self copyData:assertion.rawClientDataJSON into:&self.resp->client_data_json
			length:&self.resp->client_data_json_len];
		[self copyData:assertion.signature into:&self.resp->signature
			length:&self.resp->signature_len];
	}
	else {
		self.errorMessage = @"unexpected credential type";
	}
	self.done = YES;
	[NSApp stop:nil];
}

- (void)authorizationController:(ASAuthorizationController *)controller
	didCompleteWithError:(NSError *)error {
	if (error.code == ASAuthorizationErrorCanceled) {
		self.errorMessage = @"cancelled";
	}
	else {
		self.errorMessage = @"security key request failed";
	}
	self.done = YES;
	[NSApp stop:nil];
}

@end

static int run_request(const fido_request *req, fido_response *resp, int create, char *err,
	size_t errlen) {
	@autoreleasepool {
		[NSApplication sharedApplication];
		NSWindow *window =
			[[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 1, 1)
				styleMask:NSWindowStyleMaskBorderless
				backing:NSBackingStoreBuffered
				defer:NO];
		[window setIsVisible:YES];
		[window orderFrontRegardless];

		NSString *rpId = req->rp_id ? [NSString stringWithUTF8String:req->rp_id] : nil;
		if (!rpId) {
			set_err(err, errlen, "invalid rpId");
			return -1;
		}
		/* AuthenticationServices has no origin argument; it emits clientDataJSON from rpId. */
		(void) req->origin;
		NSData *challenge = [NSData dataWithBytes:req->challenge length:req->challenge_len];
		ASAuthorizationSecurityKeyPublicKeyCredentialProvider *provider =
			[[ASAuthorizationSecurityKeyPublicKeyCredentialProvider alloc]
				initWithRelyingPartyIdentifier:rpId];

		id request = nil;
		if (create) {
			NSString *userName = req->user_name
				? [NSString stringWithUTF8String:req->user_name]
				: @"user";
			NSData *userId = [NSData dataWithBytes:req->user_id length:req->user_id_len];
			ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest *reg =
				[provider createCredentialRegistrationRequestWithChallenge:challenge
					displayName:userName
					name:userName
					userID:userId];
			reg.userVerificationPreference =
				ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired;
			reg.attestationPreference = ASAuthorizationPublicKeyCredentialAttestationKindNone;
			if (@available(macOS 13.0, *)) {
				reg.residentKeyPreference =
					ASAuthorizationPublicKeyCredentialResidentKeyPreferenceDiscouraged;
			}
			reg.credentialParameters = @[
				[[ASAuthorizationPublicKeyCredentialParameters alloc]
					initWithAlgorithm:ASCOSEAlgorithmIdentifierES256]
			];
			request = reg;
		}
		else {
			ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest *assertion =
				[provider createCredentialAssertionRequestWithChallenge:challenge];
			assertion.userVerificationPreference =
				ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired;
			NSMutableArray *allowed = [NSMutableArray array];
			for (int i = 0; i < req->allow_count; i++) {
				NSData *cid = [NSData dataWithBytes:req->allow[i] length:req->allow_len[i]];
				ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor *desc =
					[[ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor alloc]
						initWithCredentialID:cid
						transports:@[
							ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportUSB,
							ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportNFC
						]];
				[allowed addObject:desc];
			}
			if (allowed.count > 0) {
				assertion.allowedCredentials = allowed;
			}
			request = assertion;
		}

		GhidraFidoDelegate *delegate = [[GhidraFidoDelegate alloc] init];
		delegate.window = window;
		delegate.create = create;
		delegate.resp = resp;

		ASAuthorizationController *controller =
			[[ASAuthorizationController alloc] initWithAuthorizationRequests:@[ request ]];
		controller.delegate = delegate;
		controller.presentationContextProvider = delegate;
		[controller performRequests];

		NSTimeInterval timeout = req->timeout_ms > 0 ? (req->timeout_ms / 1000.0) : 60.0;
		NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
		while (!delegate.done && [deadline timeIntervalSinceNow] > 0) {
			NSDate *step = [NSDate dateWithTimeIntervalSinceNow:0.1];
			[[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:step];
		}
		[window close];
		if (!delegate.done) {
			set_err(err, errlen, "FIDO helper timed out");
			return -1;
		}
		if (delegate.errorMessage) {
			set_err(err, errlen, delegate.errorMessage.UTF8String);
			return -1;
		}
		if (!resp->credential_id) {
			set_err(err, errlen, "security key request failed");
			return -1;
		}
		return 0;
	}
}

int fido_platform_assert(const fido_request *req, fido_response *resp, char *err,
	size_t errlen) {
	return run_request(req, resp, 0, err, errlen);
}

int fido_platform_create(const fido_request *req, fido_response *resp, char *err,
	size_t errlen) {
	return run_request(req, resp, 1, err, errlen);
}
