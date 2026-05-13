package com.example.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

/**
 * Factory for {@link GlobalSessionLimiter}.
 *
 * Registered as a Keycloak AuthenticatorFactory SPI via the META-INF/services file.
 * The factory is a singleton at the server level; the authenticator it produces is
 * also a singleton because {@link GlobalSessionLimiter} holds no mutable state.
 */
public class GlobalSessionLimiterFactory implements AuthenticatorFactory {

    private static final Logger LOG = Logger.getLogger(GlobalSessionLimiterFactory.class);

    /** SPI provider identifier — must match what is configured in the Admin Console flow. */
    public static final String PROVIDER_ID = "global-session-limiter";

    /**
     * Reusable singleton authenticator instance.
     * Safe because GlobalSessionLimiter is completely stateless.
     */
    static final GlobalSessionLimiter SINGLETON = new GlobalSessionLimiter();

    /** Requirement choices presented in the Admin Console flow editor. */
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    /** Immutable list of configurable properties shown in the Admin Console. */
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty maxSessionsProp = new ProviderConfigProperty();
        maxSessionsProp.setName(GlobalSessionLimiter.CONFIG_MAX_SESSIONS);
        maxSessionsProp.setLabel("Max Concurrent Sessions");
        maxSessionsProp.setHelpText(
            "Maximum number of concurrent active user sessions allowed across the entire realm. " +
            "When this limit is reached, new login attempts are blocked. " +
            "Must be a positive integer. Default: " + GlobalSessionLimiter.DEFAULT_MAX_SESSIONS + "."
        );
        maxSessionsProp.setType(ProviderConfigProperty.STRING_TYPE);
        maxSessionsProp.setDefaultValue(String.valueOf(GlobalSessionLimiter.DEFAULT_MAX_SESSIONS));
        CONFIG_PROPERTIES = Collections.singletonList(maxSessionsProp);
    }

    // -------------------------------------------------------------------------
    // AuthenticatorFactory contract
    // -------------------------------------------------------------------------

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getDisplayType() {
        return "Global Session Limiter";
    }

    @Override
    public String getReferenceCategory() {
        return "session-limit";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        /*
         * False: this is a realm-level infrastructure check, not a user-facing
         * setup step. Keycloak will never call setRequiredActions() for this provider.
         */
        return false;
    }

    @Override
    public String getHelpText() {
        return "Enforces a global concurrent session limit across the entire realm. " +
               "If the number of active user sessions meets or exceeds the configured maximum, " +
               "new login attempts are blocked before any credential processing occurs. " +
               "Place this step at the TOP of your Browser flow for maximum effectiveness.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    // -------------------------------------------------------------------------
    // ProviderFactory lifecycle — no server-level state to manage
    // -------------------------------------------------------------------------

    @Override
    public void init(Config.Scope config) {
        LOG.infof("GlobalSessionLimiterFactory initialized (provider-id='%s')", PROVIDER_ID);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // intentional no-op
    }

    @Override
    public void close() {
        // intentional no-op — no resources to release
    }
}
