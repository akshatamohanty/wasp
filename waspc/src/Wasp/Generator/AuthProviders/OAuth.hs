module Wasp.Generator.AuthProviders.OAuth
  ( frontendLoginUrl,
    serverLoginUrl,
    serverOauthRedirectHandlerUrl,
    providerId,
    displayName,
    scopeStr,
    OAuthAuthProvider (..),
  )
where

import Wasp.Generator.AuthProviders.Common (ProviderId, fromProviderId)
import Wasp.Generator.Common (makeJsArrayFromHaskellList)

data OAuthAuthProvider = OAuthAuthProvider
  { -- Unique identifier of the auth provider
    _providerId :: ProviderId,
    -- Used for pretty printing
    _displayName :: String,
    _requiredScope :: OAuthScope
  }

type OAuthScope = [String]

providerId :: OAuthAuthProvider -> String
providerId = fromProviderId . _providerId

displayName :: OAuthAuthProvider -> String
displayName = _displayName

-- Generates the string used in JS e.g. ["profile"] list in Haskell becomes "[\"profile\"]"
-- string which can be outputted in JS code verbatim.
scopeStr :: OAuthAuthProvider -> String
scopeStr oai = makeJsArrayFromHaskellList $ _requiredScope oai

frontendLoginUrl :: OAuthAuthProvider -> String
frontendLoginUrl oai = "/auth/login/" ++ providerId oai

serverLoginUrl :: OAuthAuthProvider -> String
serverLoginUrl oai = "/auth/" ++ providerId oai ++ "/login"

serverOauthRedirectHandlerUrl :: OAuthAuthProvider -> String
serverOauthRedirectHandlerUrl oai = "/auth/" ++ providerId oai ++ "/callback"
