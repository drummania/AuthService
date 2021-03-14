package auth;

import auth.exception.AuthServiceException;

import java.util.Set;

public interface AuthService {

    void createUser(String userId, String password) throws AuthServiceException;

    void deleteUser(String userId) throws AuthServiceException;

    void createRole(String role) throws AuthServiceException;

    void deleteRole(String role) throws AuthServiceException;

    void assignRole(String userId, String role);

    String authenticate(String userId, String password) throws AuthServiceException;

    void invalidate(String token) throws AuthServiceException;

    boolean checkRole(String token, String role) throws AuthServiceException;

    Set<String> allRoles(String token) throws AuthServiceException;
}
