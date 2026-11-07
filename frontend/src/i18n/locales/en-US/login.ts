export default {
  login: {

    success: "Signed in as {{user}}",
    failed: "Sign-in failed",
    configError: "Cannot read the authentication configuration",
    devMode: "Development mode",
    devModeHint:
      "Loopback access only: any X-User-ID header is granted platform_admin. Never use this in production.",
    devUserId: "Development user ID",
    devUserIdRequired: "Enter a development user ID",
    enterDev: "Enter the development environment",
    tokenLabel: "Platform token",
    tokenRequired: "Enter your platform token",
    signIn: "Sign in",
    tokenHint:
      "The token lives in this browser session only (sessionStorage) and is lost when the tab closes.",
    unknownMode: "Unknown authentication mode",
    unknownModeHint:
      "The backend did not return a valid AUTH_MODE — check the service configuration.",
  },
};
