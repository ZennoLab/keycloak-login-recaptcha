package org.keycloak.marjaa.providers.login.recaptcha.authenticator;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.io.InputStream;
import java.util.*;

public class TurnstileUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {
	public static final String CF_TURNSTILE_RESPONSE = "cf-turnstile-response";
	public static final String SITE_KEY = "site.key";
	public static final String SITE_SECRET = "secret";
	public static final String ACTION = "action";
	public static final String DEFAULT_ACTION = "login";
	private static final Logger logger = Logger.getLogger(TurnstileUsernamePasswordForm.class);

	private static final String MSG_TURNSTILE_NOT_CONFIGURED = "turnstileNotConfigured";
	private static final String MSG_TURNSTILE_FAILED = "turnstileFailed";

	private static final String TURNSTILE_DUMMY_TOKEN =
		"XXXX.DUMMY.TOKEN.XXXX"; // https://developers.cloudflare.com/turnstile/troubleshooting/testing/

	private String siteKey;
	private String cfAction;
	private String lang;

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		logger.info("authenticate: start");

		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

		prepareForm(context);

		super.authenticate(context);

		logger.info("authenticate: end");
	}

	@Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
		logger.info("challenge: start");

		prepareForm(context);

		Response response = super.challenge(context, formData);

		logger.info("challenge: end");

		return response;
    }

	@Override
	public void action(AuthenticationFlowContext context) {
		logger.info("action: start");
		
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		boolean success = false;
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

		String captcha = formData.getFirst(CF_TURNSTILE_RESPONSE);
		if (!Validation.isBlank(captcha)) {
			AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
			String secret = captchaConfig.getConfig().get(SITE_SECRET);
			String action = captchaConfig.getConfig().getOrDefault(ACTION, DEFAULT_ACTION);

			success = validateTurnstile(context, success, captcha, secret, action);
		}
		if (success) {
			super.action(context);
		} else {
			logger.info("action: turnstile validation returns FALSE");

			formData.remove(CF_TURNSTILE_RESPONSE);
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                challenge(context, MSG_TURNSTILE_FAILED));

			return;
		}

		logger.info("action: end");
	}

	private void prepareForm(AuthenticationFlowContext context) {
		AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
		LoginFormsProvider form = context.form();

		if (captchaConfig == null || captchaConfig.getConfig() == null
				|| captchaConfig.getConfig().get(SITE_KEY) == null
				|| captchaConfig.getConfig().get(SITE_SECRET) == null) {
			form.addError(new FormMessage(null, MSG_TURNSTILE_NOT_CONFIGURED));
			return;
		}
		Map<String, String> cfConfig = captchaConfig.getConfig();
		siteKey = cfConfig.get(SITE_KEY);
		cfAction = cfConfig.getOrDefault(ACTION, DEFAULT_ACTION);
		lang = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

		form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");
		form.setAttribute("turnstileRequired", true);
		form.setAttribute("turnstileSiteKey", siteKey);
		form.setAttribute("turnstileAction", cfAction);
		form.setAttribute("turnstileLanguage", lang);
	}

	private boolean validateTurnstile(AuthenticationFlowContext context, boolean success, String captcha, String secret, String action) {
		logger.info("validateTurnstile: start");

		HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
		HttpPost post = new HttpPost("https://challenges.cloudflare.com/turnstile/v0/siteverify");
		List<NameValuePair> formparams = new LinkedList<>();
		formparams.add(new BasicNameValuePair("secret", secret));
		formparams.add(new BasicNameValuePair("response", captcha));
		//formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
		try {
			UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
			post.setEntity(form);
			HttpResponse response = httpClient.execute(post);
			InputStream content = response.getEntity().getContent();
			try {
				Map json = JsonSerialization.readValue(content, Map.class);

				Boolean validationStatus = Boolean.TRUE.equals(json.get("success"));
				Boolean isCorrectAction = action.equals(json.get("action"));

				logger.infof("validateTurnstile: validationStatus=%s, isCorrectAction=%s, response was %s"
					, validationStatus, isCorrectAction, json.toString());
				
				success = validationStatus
					&& (captcha == TURNSTILE_DUMMY_TOKEN || isCorrectAction);
			} finally {
				content.close();
			}
		} catch (Exception e) {
			logger.errorf(e, "Failed to validate Turnstile response: %s", e.getMessage());
		}

		logger.info("validateTurnstile: end");

		return success;
	}

}
