package com.example.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * Stateless authenticator that enforces a global concurrent session limit for a realm.
 *
 * Designed to run as the FIRST step in a Browser Authentication Flow so that logins
 * are blocked before any credential processing occurs when the session cap is reached.
 *
 * Thread safety: this class holds no mutable state and is safe to use as a singleton
 * (see {@link GlobalSessionLimiterFactory#SINGLETON}).
 */
public class GlobalSessionLimiter implements Authenticator {

    private static final Logger LOG = Logger.getLogger(GlobalSessionLimiter.class);

    static final String CONFIG_MAX_SESSIONS = "maxSessions";
    static final int DEFAULT_MAX_SESSIONS = 50;

    private static final String MSG_SESSION_LIMIT_REACHED = "sessionLimitReached";

    /**
     * Entry point for the authentication flow step.
     *
     * Counts all active user sessions in the realm. If the count meets or exceeds the
     * configured limit, renders a 429 error page and marks the flow as failed.
     * On any exception during counting, the method fails open (allows login) to prevent
     * a monitoring failure from locking out all users.
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        int maxSessions = resolveMaxSessions(context);

        LOG.debugf("GlobalSessionLimiter: checking session count for realm '%s' (limit=%d)",
                realm.getName(), maxSessions);

        try {
            long activeSessionCount = countActiveSessions(context, realm);

            LOG.debugf("GlobalSessionLimiter: realm='%s' active=%d limit=%d",
                    realm.getName(), activeSessionCount, maxSessions);

            if (activeSessionCount >= maxSessions) {
                LOG.warnf(
                    "GlobalSessionLimiter: BLOCKING login — realm='%s' has %d active sessions (limit=%d).",
                    realm.getName(), activeSessionCount, maxSessions
                );
                Response errorPage = context.form()
                        .setError(MSG_SESSION_LIMIT_REACHED)
                        .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
                context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, errorPage);
                return;
            }

        } catch (Exception e) {
            /*
             * Fail-open: if the session count cannot be determined (e.g., non-Infinispan
             * store, cluster issue), log the error and allow login to proceed.
             * This prevents a monitoring outage from blocking all users.
             */
            LOG.errorf(e,
                "GlobalSessionLimiter: Failed to count active sessions in realm '%s'. " +
                "Allowing login to proceed (fail-open).",
                realm.getName()
            );
        }

        context.success();
    }

    /**
     * Counts active user sessions in the realm.
     *
     * Primary: getActiveUserSessions(realm, null) — supported by the Infinispan-backed
     * UserSessionProvider in Keycloak 18. When client is null the provider returns the
     * total USER_SESSION cache entry count for the realm.
     *
     * Fallback: if the primary call is unsupported (e.g., JPA provider throws on null
     * client), sums active client session counts from getActiveClientSessionStats().
     * Note: the fallback may overcount users who have sessions with multiple clients.
     */
    private long countActiveSessions(AuthenticationFlowContext context, RealmModel realm) {
        try {
            // Primary path: realm-wide unique user session count (Infinispan-backed)
            return context.getSession().sessions().getActiveUserSessions(realm, null);
        } catch (NullPointerException | UnsupportedOperationException primaryEx) {
            LOG.warnf(
                "GlobalSessionLimiter: getActiveUserSessions(realm, null) is not supported " +
                "by this UserSessionProvider. Falling back to client session stats. " +
                "Realm: '%s'. Cause: %s",
                realm.getName(), primaryEx.getMessage()
            );
            // Fallback: sum per-client active session counts
            Map<String, Long> stats =
                context.getSession().sessions().getActiveClientSessionStats(realm, false);
            return stats.values().stream()
                    .mapToLong(Long::longValue)
                    .sum();
        }
    }

    /**
     * Reads the configured session limit from the authenticator execution config,
     * falling back to the hardcoded default of 50 on any misconfiguration.
     */
    private int resolveMaxSessions(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null) {
            return DEFAULT_MAX_SESSIONS;
        }

        String rawValue = config.getConfig().get(CONFIG_MAX_SESSIONS);
        if (rawValue == null || rawValue.isBlank()) {
            return DEFAULT_MAX_SESSIONS;
        }

        try {
            int parsed = Integer.parseInt(rawValue.trim());
            if (parsed > 0) {
                return parsed;
            }
            LOG.warnf(
                "GlobalSessionLimiter: configured maxSessions value '%s' is not a positive integer. " +
                "Using default %d.",
                rawValue, DEFAULT_MAX_SESSIONS
            );
        } catch (NumberFormatException e) {
            LOG.warnf(
                "GlobalSessionLimiter: configured maxSessions value '%s' cannot be parsed as an integer. " +
                "Using default %d.",
                rawValue, DEFAULT_MAX_SESSIONS
            );
        }
        return DEFAULT_MAX_SESSIONS;
    }

    /**
     * No form POST is needed — the limiter either succeeds or renders an error page.
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        // intentional no-op
    }

    /**
     * Returns false so this step executes BEFORE Keycloak attempts to identify the user.
     * This is intentional: the limit is per-realm, not per-user.
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    /**
     * Always returns true: the limiter is applicable to every authentication attempt
     * regardless of the user or their configuration.
     */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    /** No required actions to assign — the limiter never prompts for user remediation. */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // intentional no-op
    }

    /** Stateless — no resources to release. */
    @Override
    public void close() {
        // intentional no-op
    }
}
