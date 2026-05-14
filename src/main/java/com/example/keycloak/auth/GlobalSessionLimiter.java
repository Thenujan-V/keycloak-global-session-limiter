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

                context.forceChallenge(buildLimitChallenge(context));
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
     * Counts active user sessions in the realm via per-client session stats.
     *
     * Uses getActiveClientSessionStats() which is supported by all UserSessionProvider
     * implementations (Infinispan and JPA). The sum of per-client counts may overcount
     * users who hold sessions with multiple clients, but is intentionally conservative
     * for a session limiter.
     */
    private long countActiveSessions(AuthenticationFlowContext context, RealmModel realm) {
        Map<String, Long> stats =
            context.getSession().sessions().getActiveClientSessionStats(realm, false);
        if (stats == null || stats.isEmpty()) {
            return 0L;
        }
        return stats.values().stream()
                .mapToLong(Long::longValue)
                .sum();
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
     * Handles form submission from the session-limit challenge page.
     *
     * Re-runs the session count check: if still over limit, re-renders the blocked page;
     * otherwise allows the flow to continue (handles the rare race where a session ended
     * between the initial challenge and the form submit).
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        int maxSessions = resolveMaxSessions(context);
        try {
            long activeSessionCount = countActiveSessions(context, realm);
            if (activeSessionCount >= maxSessions) {
                context.forceChallenge(buildLimitChallenge(context));
                return;
            }
        } catch (Exception e) {
            LOG.errorf(e,
                "GlobalSessionLimiter: Failed to count active sessions in realm '%s' during action. " +
                "Allowing login to proceed (fail-open).",
                realm.getName()
            );
        }
        context.success();
    }

    private Response buildLimitChallenge(AuthenticationFlowContext context) {
        return context.form()
                .setAttribute("login", new java.util.HashMap<String, Object>())
                .setError(MSG_SESSION_LIMIT_REACHED)
                .createForm("login.ftl");
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
