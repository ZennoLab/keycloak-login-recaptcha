package org.keycloak.marjaa.providers.login.recaptcha.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.DisplayTypeAuthenticatorFactory;
import org.keycloak.authentication.authenticators.console.ConsoleUsernamePasswordAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class TurnstileUsernamePasswordFormFactory  implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {

    public static final String PROVIDER_ID = "turnstile-u-p-form";
    public static final TurnstileUsernamePasswordForm SINGLETON = new TurnstileUsernamePasswordForm();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public Authenticator createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return SINGLETON;
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return ConsoleUsernamePasswordAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }
    
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Turnstile Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form + Cloudflare Turnstile";
    }

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(TurnstileUsernamePasswordForm.SITE_KEY);
        property.setLabel("Tunrstile Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Cloudflare Turnstile Site Key");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(TurnstileUsernamePasswordForm.SITE_SECRET);
        property.setLabel("Turnstile Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Cloudflare Turnstile Secret");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(TurnstileUsernamePasswordForm.ACTION);
        property.setLabel("Action");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("A value that can be used to differentiate widgets under the same Site Key in analytics. Default value is 'login'");
        CONFIG_PROPERTIES.add(property);
    }

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}