import {
    createAuthClient
} from "better-auth/react";

import {passkeyClient} from "better-auth/client/plugins"
import { toast } from "sonner";

import {
	adminClient,
	deviceAuthorizationClient,
	genericOAuthClient,
	lastLoginMethodClient,
	multiSessionClient,
	oidcClient,
	oneTapClient,
	organizationClient,
	twoFactorClient,
} from "better-auth/client/plugins";

export const authClient = createAuthClient({
    baseURL: process.env.NEXT_PUBLIC_APP_URL,
    	plugins: [
		organizationClient(),
		twoFactorClient({
			onTwoFactorRedirect() {
				window.location.href = "/two-factor";
			},
		}),
		passkeyClient(),
		adminClient(),
		multiSessionClient(),
		oneTapClient({
			clientId: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!,
			promptOptions: {
				maxAttempts: 1,
			},
		}),
		oidcClient(),
		genericOAuthClient(),
		deviceAuthorizationClient(),
		lastLoginMethodClient(),
	],
	fetchOptions: {
		onError(e) {
			if (e.error.status === 429) {
				toast.error("Too many requests. Please try again later.");
			}
		},
	},

})

export const {
	signUp,
	signIn,
	signOut,
    passkey,
	useSession,
	organization,
	useListOrganizations,
	useActiveOrganization,
	useActiveMember,
	useActiveMemberRole,
} = authClient;
