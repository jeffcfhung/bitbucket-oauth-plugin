package org.jenkinsci.plugins;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;


import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;

import org.jenkinsci.plugins.api.JiraApiService;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.scribe.model.Token;
import org.springframework.dao.DataAccessException;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;

import jenkins.model.Jenkins;

import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;


public class BitbucketSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = BitbucketSecurityRealm.class.getName() + ".referer";
    private static final String ACCESS_TOKEN_ATTRIBUTE = BitbucketSecurityRealm.class.getName() + ".access_token";
    private static final Logger LOGGER = Logger.getLogger(BitbucketSecurityRealm.class.getName());

    private String serverURL;
    private String clientID;
    private String clientSecret;

    @DataBoundConstructor
    public BitbucketSecurityRealm(String serverURL, String clientID, String clientSecret) {
        super();
        this.serverURL = Util.fixEmptyAndTrim(serverURL);
        this.clientID = Util.fixEmptyAndTrim(clientID);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    }

    public BitbucketSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "BitbucketSecurityRealm()");
    }

    /**
     * @return the serverURL
     */
    public String getServerURL() {
        return serverURL;
    }

    /**
     * @param serverURL the severURL to set
     */
    public void setServerURL(String serverURL) { this.serverURL = serverURL; }


    /**
     * @return the clientID
     */
    public String getClientID() {
        return clientID;
    }

    /**
     * @param clientID the clientID to set
     */
    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    /**
     * @return the clientSecret
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * @param clientSecret the clientSecret to set
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {

        // Test code
        try {
            UserDetails uds = loadUserByUsername("test");
            LOGGER.log(Level.ALL, "User details before login " + uds);
        }
        catch (Exception e) {
            LOGGER.fine("User first time login");
        }

        // End of test code

        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
        	throw new RuntimeException("Jenkins is not started yet.");
        }
		String rootUrl = jenkins.getRootUrl();
        if (StringUtils.endsWith(rootUrl, "/")) {
            rootUrl = StringUtils.left(rootUrl, StringUtils.length(rootUrl) - 1);
        }
        String callback = rootUrl + "/securityRealm/finishLogin";

        JiraApiService bitbucketApiService = new JiraApiService(serverURL, clientID, clientSecret, callback);

        Token requestToken = bitbucketApiService.createRquestToken();
        request.getSession().setAttribute(ACCESS_TOKEN_ATTRIBUTE, requestToken);

        return new HttpRedirect(bitbucketApiService.createAuthorizationCodeURL(requestToken));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("oauth_verifier");
        LOGGER.log(Level.ALL, "code: " + code);

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }

        Token requestToken = (Token) request.getSession().getAttribute(ACCESS_TOKEN_ATTRIBUTE);

        Token accessToken = new JiraApiService(serverURL, clientID, clientSecret).getTokenByAuthorizationCode(code, requestToken);

        if (!accessToken.isEmpty()) {
            BitbucketAuthenticationToken auth = new BitbucketAuthenticationToken(accessToken, serverURL, clientID, clientSecret);
            SecurityContextHolder.getContext().setAuthentication(auth);
            LOGGER.log(Level.ALL, "User name:" + auth.getName() + ", authToken: " + auth);

            User u = User.current();
            if (u != null) {
                u.setFullName(auth.getFullName());
                if(isMailerPluginPresent()) {
                    try {
                        // legacy hack. mail support has moved out to a separate plugin
                        Class<?> up = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("hudson.tasks.Mailer$UserProperty");
                        Constructor<?> c = up.getDeclaredConstructor(String.class);
                        u.addProperty((UserProperty)c.newInstance(auth.getEmail()));
                    } catch (ReflectiveOperationException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

        } else {
            LOGGER.log(Level.SEVERE, "doFinishLogin() accessToken = null");
        }

        // redirect to referer
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityRealm.SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof BitbucketAuthenticationToken) {
                    return authentication;
                }

                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username)  throws UserMayOrMayNotExistException, DataAccessException {
                throw new UserMayOrMayNotExistException("Cannot verify users in this context");
            }
        });
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails result;
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) {
            throw new UsernameNotFoundException("BitbucketAuthenticationToken = null, no known user: " + username);
        }

        LOGGER.log(Level.ALL, "LoadUserByUsername token: " + token);
        BitbucketAuthenticationToken authToken;

        if (token instanceof BitbucketAuthenticationToken) {
            authToken = (BitbucketAuthenticationToken) token;
        }else {
          throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
        }
        LOGGER.log(Level.ALL, "Get access token by user name:" + authToken.getAccessToken());
        result = new JiraApiService(serverURL, clientID, clientSecret).getUserByToken(authToken.getAccessToken());
        if (result == null) {
            throw new UsernameNotFoundException("User does not exist for login: " + username);
        }
        return result;
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
        throw new UsernameNotFoundException("groups not supported");
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    public static final class ConverterImpl implements Converter {

        public boolean canConvert(Class type) {
            return type == BitbucketSecurityRealm.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            BitbucketSecurityRealm realm = (BitbucketSecurityRealm) source;

            writer.startNode("serverURL");
            writer.setValue(realm.getServerURL());
            writer.endNode();

            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

            String node = reader.getNodeName();

            reader.moveDown();

            BitbucketSecurityRealm realm = new BitbucketSecurityRealm();

            node = reader.getNodeName();

            String value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

            reader.moveDown();

            node = reader.getNodeName();

            value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

            if (reader.hasMoreChildren()) {
                reader.moveDown();

                node = reader.getNodeName();

                value = reader.getValue();

                setValue(realm, node, value);

                reader.moveUp();
            }
            return realm;
        }

        private void setValue(BitbucketSecurityRealm realm, String node, String value) {

            if (node.equalsIgnoreCase("serverURL")) {
                realm.setServerURL(value);
            } else if (node.equalsIgnoreCase("clientid")) {
                realm.setClientID(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
            } else {
                throw new ConversionException("invalid node value = " + node);
            }

        }
    }

    @Restricted(NoExternalUse.class)
    public boolean isMailerPluginPresent() {
        try {
            // mail support has moved to a separate plugin
            return null != Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("hudson.tasks.Mailer$UserProperty");
        } catch (ClassNotFoundException e) {
            LOGGER.finer("Mailer plugin not present");
        }
        return false;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getHelpFile() {
            return "/plugin/bitbucket-oauth/help/help-security-realm.html";
        }

        @Override
        public String getDisplayName() {
            return "Bitbucket OAuth Plugin";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }
    }

}
