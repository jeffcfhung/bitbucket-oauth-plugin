package org.jenkinsci.plugins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.api.JiraApiService;
import org.jenkinsci.plugins.api.JiraUser;
import org.scribe.model.Token;

import java.util.logging.Logger;

public class BitbucketAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -7826610577724673531L;
    private static final Logger LOGGER = Logger.getLogger(BitbucketAuthenticationToken.class.getName());

    private Token accessToken;
    private JiraUser bitbucketUser;

    public BitbucketAuthenticationToken(Token accessToken, String serverURL, String apiKey, String apiSecret) {
        this.accessToken = accessToken;
        this.bitbucketUser = new JiraApiService(serverURL, apiKey, apiSecret).getJiraUserByToken(accessToken);

        boolean authenticated = false;

        if (bitbucketUser != null) {
            authenticated = true;
        }

        setAuthenticated(authenticated);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return this.bitbucketUser != null ? this.bitbucketUser.getAuthorities() : new GrantedAuthority[0];
    }

    /**
     * @return the accessToken
     */
    public Token getAccessToken() {
        return accessToken;
    }

    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }

    @Override
    public String getName() {
        return (bitbucketUser != null ? bitbucketUser.getUsername() : null);
    }

    public String getEmail() {
        return (bitbucketUser != null ? bitbucketUser.email : null);
    }

    public String getFullName() {
        return (bitbucketUser != null ? bitbucketUser.fullName : null);
    }
}
