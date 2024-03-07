{{={= =}=}}
import { Router, Request as ExpressRequest } from "express";
import { GitHub, generateState } from "arctic";

import { HttpError } from 'wasp/server';
import { handleRejection } from "wasp/server/utils";
import type { ProviderConfig } from "wasp/auth/providers/types";
import { finishOAuthFlowAndGetRedirectUri } from "../oauth/user.js";
import { getStateCookieName, getValueFromCookie, setValueInCookie } from "../oauth/cookies.js";
import { callbackPath } from "../oauth/redirect.js";
import { ensureEnvVarsForProvider } from "../oauth/env.js";
import { mergeDefaultAndUserConfig } from "../oauth/config.js";

{=# userSignupFields.isDefined =}
{=& userSignupFields.importStatement =}
const _waspUserSignupFields = {= userSignupFields.importIdentifier =}
{=/ userSignupFields.isDefined =}
{=^ userSignupFields.isDefined =}
const _waspUserSignupFields = undefined
{=/ userSignupFields.isDefined =}
{=# configFn.isDefined =}
{=& configFn.importStatement =}
const _waspUserDefinedConfigFn = {= configFn.importIdentifier =}
{=/ configFn.isDefined =}
{=^ configFn.isDefined =}
const _waspUserDefinedConfigFn = undefined
{=/ configFn.isDefined =}

const _waspConfig: ProviderConfig = {
    id: "{= providerId =}",
    displayName: "{= displayName =}",
    createRouter(provider) {
        const router = Router();

        const env = ensureEnvVarsForProvider(
            ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"],
            provider
        );

        const github = new GitHub(
            env.GITHUB_CLIENT_ID,
            env.GITHUB_CLIENT_SECRET,
        );

        const config = mergeDefaultAndUserConfig({
            scopes: {=& requiredScopes =},
        }, _waspUserDefinedConfigFn);

        router.get('/login',handleRejection(async (_req, res) => {
            const state = generateState();
            setValueInCookie(getStateCookieName(provider.id), state, res);

            const url = await github.createAuthorizationURL(state, config);
            return res.status(302)
                .setHeader("Location", url.toString())
                .end();
        }));

        router.get(`/${callbackPath}`, handleRejection(async (req, res) => {    
            try {
                const { code } =  getDataFromCallback(req);
                const { accessToken } = await github.validateAuthorizationCode(code);
                const { providerProfile, providerUserId } = await getGithubProfile(accessToken);
                const { redirectUri } =  await finishOAuthFlowAndGetRedirectUri(
                    provider,
                    providerProfile,
                    providerUserId,
                    _waspUserSignupFields,
                );

                // Redirect to the client with the one time code
                return res
                    .status(302)
                    .setHeader("Location", redirectUri)
                    .end();
            } catch (e) {
                // TODO: handle different errors
                console.error(e);
        
                // TODO: it makes sense to redirect to the client with the OAuth erorr!
                throw new HttpError(500, "Something went wrong");
            }
        }));

        function getDataFromCallback(req: ExpressRequest): { code: string } {
            const storedState = getValueFromCookie(
                getStateCookieName(provider.id),
                req
            );
            const state = req.query.state;
            const code = req.query.code;
    
            if (
                !storedState ||
                !state ||
                storedState !== state ||
                typeof code !== "string"
            ) {
                throw new Error("Invalid state or code");
            }

            return { code }
        }

        async function getGithubProfile(accessToken: string): Promise<{
            providerProfile: unknown;
            providerUserId: string;
        }> {
            const response = await fetch("https://api.github.com/user", {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            });
            const providerProfile = (await response.json()) as {
                id?: string;
                emails?: unknown[];
            };
            
            if (!providerProfile.id) {
               throw new Error("Invalid profile");
            }

            const scopes = config.scopes as string[];
            // Using the logic from https://github.com/cfsghost/passport-github/blob/master/lib/strategy.js#L118C24-L120C10
            const isEmailAccessAllowed = scopes.some((scope) => {
                return scope === 'user' || scope === 'user:email';
            });
            if (isEmailAccessAllowed) {
                const emailsResponse = await fetch("https://api.github.com/user/emails", {
                    headers: {
                        Authorization: `Bearer ${accessToken}`,
                    },
                });
                const emails = (await emailsResponse.json()) as unknown[];
                providerProfile.emails = emails;
            }

            return { providerProfile, providerUserId: `${providerProfile.id}` };
        }

        return router;
    },
}

export default _waspConfig;
