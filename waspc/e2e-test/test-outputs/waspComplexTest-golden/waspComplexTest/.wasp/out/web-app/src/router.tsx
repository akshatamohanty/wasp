import React from 'react'
import { Route, Switch, BrowserRouter as Router } from 'react-router-dom'
import __userDefinedApp from '../../../../src/client/App.jsx'

import createAuthRequiredPage from "./auth/pages/createAuthRequiredPage"

import { MainPage } from '../../../../src/MainPage'

import OAuthCodeExchange from "./auth/pages/OAuthCodeExchange"

import { routes } from 'wasp/client/router'

export const routeNameToRouteComponent = {
  RootRoute: MainPage,
} as const;

const router = (
  <Router basename="/">
    <__userDefinedApp>
    <Switch>
      {Object.entries(routes).map(([routeKey, route]) => (
        <Route
          exact
          key={routeKey}
          path={route.to}
          component={routeNameToRouteComponent[routeKey]}
        />
      ))}
      <Route exact path="/auth/login/google">
        <OAuthCodeExchange pathToApiServerRouteHandlingOauthRedirect="/auth/google/callback" />
      </Route>
    </Switch>
    </__userDefinedApp>
  </Router>
)

export default router
