import { config } from 'wasp/server'

export const callbackPath = 'callback'

export function getRedirectUriForCallback(providerName: string) {
  return `${config.serverUrl}/auth/${providerName}/${callbackPath}`;
}

export function getRedirectUriForOneTimeCode(oneTimeCode: string) {
  return `${config.frontendUrl}/oauth/callback#${oneTimeCode}`;
}
