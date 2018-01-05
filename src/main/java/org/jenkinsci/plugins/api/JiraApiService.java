package org.jenkinsci.plugins.api;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.IOUtils;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;

import com.google.gson.Gson;

import java.util.logging.Level;
import java.util.logging.Logger;


public class JiraApiService extends BitbucketApiService {
    private static final Logger LOGGER = Logger.getLogger(JiraApiService.class.getName());

    public JiraApiService(String serverURL, String apiKey, String apiSecret) {
        super(serverURL, apiKey, apiSecret, null);
    }

    public JiraApiService(String serverURL, String apiKey, String apiSecret, String callback) {
        super(serverURL, apiKey, apiSecret, callback);
    }

    public JiraUser getJiraUserByToken(Token accessToken) {
        OAuthRequest request = new OAuthRequest(Verb.GET, API_ENDPOINT + "/rest/api/latest/currentUser");
        service.signRequest(accessToken, request);
        Response response = request.send();
        String json = response.getBody();
        LOGGER.log(Level.ALL, json);
        Gson gson = new Gson();
        JiraUser user = gson.fromJson(json, JiraUser.class);
        return user;
    }

    @Override
    public UserDetails getUserByUsername(String username) {
        InputStreamReader reader = null;
        UserDetails user = null;
        try {
            URL url = new URL(API_ENDPOINT + "/rest/api/latest/search/users?searchTerm=" + username);
            reader = new InputStreamReader(url.openStream(), "UTF-8");
            String response = IOUtils.toString(reader);
            JSONObject json = (JSONObject) JSONSerializer.toJSON(response);
            if (json == null) {
                LOGGER.warning("Could not parse JSON response: " + response);
                return user;
            }
            JSONArray searchResults = json.getJSONArray("searchResults");
            if (searchResults.size() == 0) {
                LOGGER.warning("Could not get user with data size 0: " + response);
                return user;
            }

            JiraUser jiraUser = new JiraUser();
            JSONObject jsonUser = searchResults.getJSONObject(0).getJSONObject("searchEntity");
            jiraUser.name = jsonUser.getString("id");
            jiraUser.fullName = jsonUser.getString("fullName");
            user = jiraUser;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(reader);
        }

        return user;
    }
}
