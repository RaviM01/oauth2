import { AuthConfig } from 'angular-oauth2-oidc';

export const authCodeFlowConfig: AuthConfig = {
  issuer: 'http://localhost:9000',
  redirectUri: window.location.origin + '/index.html',
  clientId: 'config-portal',
  responseType: 'code',
  scope: 'openid profile',
  showDebugInformation: true,
  timeoutFactor: 0.01,
  checkOrigin: false,
  requireHttps: false,
  oidc: true
};
