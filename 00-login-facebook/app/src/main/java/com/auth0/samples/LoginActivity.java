package com.auth0.samples;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;
import com.facebook.AccessToken;
import com.facebook.CallbackManager;
import com.facebook.FacebookCallback;
import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import com.facebook.GraphRequest;
import com.facebook.GraphResponse;
import com.facebook.login.LoginResult;
import com.facebook.login.widget.LoginButton;

import org.json.JSONException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LoginActivity extends AppCompatActivity {

    private static final String TAG = LoginActivity.class.getSimpleName();
    private static final String FACEBOOK_SUBJECT_TOKEN_TYPE = "http://auth0.com/oauth/token-type/facebook-info-session-access-token";
    private static final List<String> FACEBOOK_PERMISSIONS = Arrays.asList("public_profile", "email");
    private static final String AUTH0_SCOPE = "openid email profile offline_access";


    private CallbackManager fbCallbackManager;
    private AuthenticationAPIClient auth0Client;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_login);

        Auth0 account = new Auth0(getString(R.string.com_auth0_client_id), getString(R.string.com_auth0_domain));
        auth0Client = new AuthenticationAPIClient(account);

        fbCallbackManager = CallbackManager.Factory.create();

        LoginButton loginButton = findViewById(R.id.login_button);
        loginButton.setPermissions(FACEBOOK_PERMISSIONS);
        loginButton.registerCallback(fbCallbackManager, new FacebookCallback<LoginResult>() {
            @Override
            public void onSuccess(LoginResult result) {
                //1. Logged in to Facebook
                AccessToken accessToken = result.getAccessToken();
                performLogin(accessToken);
            }

            @Override
            public void onCancel() {
                Log.i(TAG, "Facebook sign-in cancelled");
            }

            @Override
            public void onError(FacebookException error) {
                Log.e(TAG, "Error " + error.getMessage());
                //Handle Facebook authentication error
            }
        });
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        fbCallbackManager.onActivityResult(requestCode, resultCode, data);
        super.onActivityResult(requestCode, resultCode, data);
    }

    private void performLogin(@NonNull final AccessToken accessToken) {
        final String token = accessToken.getToken();
        fetchSessionToken(token, new SimpleCallback<String>() {
            @Override
            public void onResult(@NonNull final String sessionToken) {
                //2. Obtained the Facebook session token
                fetchUserProfile(token, accessToken.getUserId(), new SimpleCallback<String>() {

                    @Override
                    public void onResult(@NonNull String jsonProfile) {
                        //3. Obtained the Facebook user profile
                        exchangeTokens(sessionToken, jsonProfile, new SimpleCallback<Credentials>() {

                            @Override
                            public void onResult(@NonNull Credentials credentials) {
                                Log.i(TAG, "Logged in to Auth0");
                                /*
                                 * 4. Logged in!
                                 *  Use access token to call API
                                 *  or consume ID token locally
                                 */
                            }

                            @Override
                            public void onError(@NonNull Throwable cause) {
                                Log.e(TAG, "Error exchanging tokens", cause);
                                //Handle token exchange error
                            }
                        });
                    }

                    @Override
                    public void onError(@NonNull Throwable cause) {
                        Log.e(TAG, "Error fetching the profile", cause);
                        //Handle profile request error
                    }
                });
            }

            @Override
            public void onError(@NonNull Throwable cause) {
                Log.e(TAG, "Error fetching the session token", cause);
                //Handle session token request error
            }
        });
    }

    private void fetchSessionToken(String token, final SimpleCallback<String> callback) {
        Bundle params = new Bundle();
        params.putString("grant_type", "fb_attenuate_token");
        params.putString("fb_exchange_token", token);
        params.putString("client_id", getString(R.string.facebook_app_id));

        GraphRequest request = new GraphRequest();
        request.setParameters(params);
        request.setGraphPath("oauth/access_token");
        request.setCallback(new GraphRequest.Callback() {
            @Override
            public void onCompleted(GraphResponse response) {
                FacebookRequestError error = response.getError();
                if (error != null) {
                    //Failed to fetch session token
                    callback.onError(error.getException());
                    return;
                }
                try {
                    String fbSessionToken = response.getJSONObject().getString("access_token");
                    callback.onResult(fbSessionToken);
                } catch (JSONException e) {
                    //Failed to parse session token
                    callback.onError(e);
                }
            }
        });
        request.executeAsync();
    }

    private void fetchUserProfile(String token, String userId, final SimpleCallback<String> callback) {
        Bundle params = new Bundle();
        params.putString("access_token", token);
        params.putString("fields", "first_name,last_name,email");

        GraphRequest request = new GraphRequest();
        request.setParameters(params);
        request.setGraphPath(userId);
        request.setCallback(new GraphRequest.Callback() {
            @Override
            public void onCompleted(GraphResponse response) {
                FacebookRequestError error = response.getError();
                if (error != null) {
                    //Failed to fetch user profile
                    callback.onError(error.getException());
                    return;
                }
                //Handle back the profile as received
                callback.onResult(response.getRawResponse());
            }
        });
        request.executeAsync();
    }

    private void exchangeTokens(@NonNull String sessionToken, @NonNull String userProfile, @NonNull final SimpleCallback<Credentials> callback) {
        Map<String, Object> params = new HashMap<>();
        params.put("user_profile", userProfile);

        auth0Client.loginWithNativeSocialToken(sessionToken, FACEBOOK_SUBJECT_TOKEN_TYPE)
                .setScope(AUTH0_SCOPE)
                .addAuthenticationParameters(params)
                .start(new BaseCallback<Credentials, AuthenticationException>() {
                    @Override
                    public void onSuccess(Credentials credentials) {
                        callback.onResult(credentials);
                    }

                    @Override
                    public void onFailure(AuthenticationException error) {
                        callback.onError(error);
                    }
                });
    }

    private interface SimpleCallback<T> {
        void onResult(@NonNull T result);

        void onError(@NonNull Throwable cause);
    }

}