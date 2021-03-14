package auth;

import auth.entity.Password;
import auth.exception.AuthServiceException;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AuthServiceImpl provide authentication and authorization service.
 * The service allows users to be authenticated, and authorizes
 * different behavior.
 */
public class AuthServiceImpl implements AuthService {

    public static final boolean ALLOW_ANONYMOUS_USER = false;
    public static final String ANONYMOUS_USERNAME = "anonymous";
    public static final String ANONYMOUS_USERPW = "password";
    public static final int TOKEN_LENGTH = 24;

    private final Map<String, Set<String>> authorization; // user id to role map
    private final Set<String> roles;                      // set of role
    private final Map<String, Password> users;            // user id to password map
    private final Map<String, String> tokens;             // token to user id map

    public AuthServiceImpl() {

        roles = new HashSet();
        users = new ConcurrentHashMap();
        authorization = new ConcurrentHashMap();
        tokens = new ConcurrentHashMap();
    }

    /**
     * Create user based on given username and password
     *
     * @param userId   user id
     * @param password password of the user in plain text
     * @throws AuthServiceException if user already exist
     */
    public void createUser(String userId, String password) throws AuthServiceException {

        if (users.containsKey(userId)) {
            throw new AuthServiceException("User already exist");
        }
        users.put(userId, new Password(password));
    }

    /**
     * Delete given user
     *
     * @param userId user id
     * @throws AuthServiceException if user does not exist
     */
    public void deleteUser(String userId) throws AuthServiceException {

        if (!users.containsKey(userId)) {
            throw new AuthServiceException("User does not exist");
        }
        users.remove(userId);
    }

    /**
     * Create role
     *
     * @param role name of the role
     * @throws AuthServiceException if role is already exist
     */
    public void createRole(String role) throws AuthServiceException {

        if (roles.contains(role)) {
            throw new AuthServiceException("Role already exist");
        }
        Collections.synchronizedSet(roles).add(role);
    }

    /**
     * Delete given role
     *
     * @param role name of the role
     * @throws AuthServiceException if role does not exist
     */
    public void deleteRole(String role) throws AuthServiceException {

        if (!roles.contains(role)) {
            throw new AuthServiceException("Role does not exist");
        }
        Collections.synchronizedSet(roles).remove(role);
    }

    /**
     * Assign role to user
     *
     * @param userId user id
     * @param role   name of the role
     */
    public void assignRole(String userId, String role) {

        if (isUserExist(userId) && isRoleExist(role)) {
            authorization.computeIfAbsent(userId, x -> new HashSet()).add(role);
        }
    }

    /**
     * Authenicate user with given password
     *
     * @param userId   user id
     * @param password given password
     * @throws AuthServiceException if no user is found
     */
    public String authenticate(String userId, String password) throws AuthServiceException {
        final Password userPassword = users.get(userId);
        if (userPassword == null) {
            throw new AuthServiceException("No user found");
        }
        return userPassword.match(password) ? generateNewToken(userId) : "";
    }

    /**
     * Authenicate anonymous user
     *
     * @throws AuthServiceException if anonymous user is not allowed
     */
    public String authenticate() throws AuthServiceException {

        if (!ALLOW_ANONYMOUS_USER) {
            throw new AuthServiceException("Anonymous user is not allowed");
        }

        createUser(ANONYMOUS_USERNAME, ANONYMOUS_USERPW);
        return generateNewToken(ANONYMOUS_USERNAME);
    }

    private String generateNewToken(String userId) {

        final SecureRandom secureRandom = new SecureRandom();
        final Base64.Encoder base64Encoder = Base64.getUrlEncoder();
        final byte[] randomBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(randomBytes);

        final String token = base64Encoder.encodeToString(randomBytes);
        tokens.put(token, userId);

        return token;
    }

    /**
     * Return nothing, the token is no longer valid after the call
     *
     * @param token auth token to be invalidated
     * @throws AuthServiceException if token does not exist
     */
    public void invalidate(String token) throws AuthServiceException {
        if (!tokens.keySet().contains(token)) {
            throw new AuthServiceException("Token does not exist");
        }
        tokens.remove(token);
    }

    /**
     * Return true if role is supported, false otherwise
     *
     * @param token auth token
     * @param role  role to be checked
     * @throws AuthServiceException if token is invalid
     */
    public boolean checkRole(String token, String role) throws AuthServiceException {
        return allRoles(token).contains(role);
    }

    /**
     * Return all roles for the user
     *
     * @param token auth token
     * @throws AuthServiceException if token is invalid
     */
    public Set<String> allRoles(String token) throws AuthServiceException {

        String user = tokens.get(token);
        if (user == null) {
            throw new AuthServiceException("Token is invalid");
        }

        return authorization.get(user);
    }

    protected boolean isUserExist(String userId) {
        return users.keySet().contains(userId);
    }

    protected boolean isRoleExist(String role) {
        return roles.contains(role);
    }

    protected Set<String> getUserRole(String userId) {
        final Set<String> roles = authorization.get(userId);
        return null == roles ? Collections.emptySet() : roles;
    }
}
