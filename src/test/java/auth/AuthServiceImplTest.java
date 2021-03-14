package auth;

import auth.exception.AuthServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceImplTest {

    AuthServiceImpl authService;
    private String authToken;

    @BeforeEach
    void setup() {
        authService = new AuthServiceImpl();
    }

    @Test
    void testCreateUser() throws Exception {

        authService.createUser("User1", "aa093jl07");
        assertTrue(authService.isUserExist("User1"));
    }

    @Test
    void testCreateAlreadyExistUser() throws Exception {

        authService.createUser("User1", "aa093jl07");
        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.createUser("User1", "aa093jl07");
            ;
        });
        assertTrue(e.getMessage().contains("User already exist"));

    }

    @Test
    void testDeleteUser() throws Exception {
        authService.createUser("User1", "aa093jl07");
        assertTrue(authService.isUserExist("User1"));
        authService.deleteUser("User1");
        assertFalse(authService.isUserExist("User1"));
    }

    @Test
    void testDeleteNonExistUser() {

        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.deleteUser("NonExistUser");
        });
        assertTrue(e.getMessage().contains("User does not exist"));
    }

    @Test
    void testCreateRole() throws Exception {
        authService.createRole("Support");
        assertTrue(authService.isRoleExist("Support"));
    }

    @Test
    void testCreateAlreadyExistRole() throws Exception {

        authService.createRole("Support");
        assertTrue(authService.isRoleExist("Support"));

        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.createRole("Support");
        });
        assertTrue(e.getMessage().contains("Role already exist"));
    }

    @Test
    void testDeleteRole() throws Exception {
        authService.createRole("Admin");
        assertTrue(authService.isRoleExist("Admin"));
        authService.deleteRole("Admin");
        assertFalse(authService.isRoleExist("Admin"));
    }

    @Test
    void testDeleteNonExistRole() {

        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.deleteRole("NonExistRole");
        });
        assertTrue(e.getMessage().contains("Role does not exist"));
    }

    @Test
    void assignRoleSuccess() throws Exception {

        authService.createUser("User3", "aa093jl07");
        authService.createRole("Admin");

        authService.assignRole("User3", "Admin");
        assertTrue(authService.getUserRole("User3").contains("Admin"));
        assertTrue(authService.getUserRole("User3").size() == 1);
    }

    @Test
    void testAssignSameUserToSameRoleMultipleTime() throws Exception {

        authService.createUser("User3", "aa093jl07");
        authService.createRole("Admin");
        authService.assignRole("User3", "Admin");
        authService.assignRole("User3", "Admin");
        authService.assignRole("User3", "Admin");
        assertTrue(authService.getUserRole("User3").contains("Admin"));
        assertTrue(authService.getUserRole("User3").size() == 1);
    }

    @Test
    void testAssignUserToNonExistRole() throws Exception {

        authService.createUser("User3", "aa093jl07");
        assertTrue(authService.getUserRole("NonExistUser").size() == 0);
    }

    @Test
    void testAssignNonExistUserToRole() throws Exception {

        authService.createRole("Admin");
        authService.assignRole("NonExistUser", "Admin");
        assertTrue(authService.getUserRole("NonExistUser").size() == 0);
    }

    @Test
    void testAuthenticateSuccess() throws Exception {
        final String username = "User1";
        final String password = "aa093jl08";
        authService.createUser(username, password);
        assertTrue(authService.authenticate(username, password).length() > 0,
                "Token is generated");
    }

    @Test
    void testAuthenticateFail() throws Exception {

        final String username = "User1";
        final String password = "aa093jl08";
        authService.createUser(username, password);
        assertTrue(authService.authenticate(username, "wrongPassword").isEmpty(),
                "No token is generated");
    }

    @Test
    void testAuthenticateNonExistUser() {

        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.authenticate("NonExistUser", "abc12456");
        });
        assertTrue(e.getMessage().contains("No user found"));
    }

    @Test
    void invalidate() throws Exception {

        final String username = "User1";
        final String password = "aa093jl08";
        final String role = "Admin";

        authService.createUser(username, password);
        authToken = authService.authenticate(username, password);
        assertTrue(authToken.length() > 0);

        authService.createRole(role);
        authService.assignRole(username, role);

        assertTrue(authService.checkRole(authToken, role));

        // check role after token is invalidated
        authService.invalidate(authToken);
        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.checkRole(authToken, role);
        });

        assertTrue(e.getMessage().contains("Token is invalid"));

        // try to invalidate invalidated token
        Exception ex = assertThrows(AuthServiceException.class, () -> {
            authService.invalidate(authToken);
            ;
        });

        assertTrue(e.getMessage().contains("Token is invalid"));
    }

    @Test
    void checkRole() throws Exception {

        final String username = "User1";
        final String password = "aa093jl08";
        final String role = "Admin";

        authService.createUser(username, password);
        authToken = authService.authenticate(username, password);
        assertTrue(authToken.length() > 0);

        authService.createRole(role);
        authService.assignRole(username, role);

        assertTrue(authService.checkRole(authToken, role));
        assertFalse(authService.checkRole(authToken, "NonAssignedRole"));
    }

    @Test
    void checkRoleWithInvalidToken() throws Exception {

        authService.createUser("User1", "pass1");
        authService.createRole("Admin");
        authService.assignRole("User1", "Admin");
        authToken = authService.authenticate("User1", "pass1");
        assertTrue(authToken.length() > 0);

        Exception e = assertThrows(AuthServiceException.class, () -> {
            assertFalse(authService.checkRole("abc", "Admin"));
        });

        assertTrue(e.getMessage().contains("Token is invalid"));
    }

    @Test
    void allRoles() throws AuthServiceException {

        final String username = "User1";
        final String password = "aa093jl08";

        authService.createUser(username, password);
        authToken = authService.authenticate(username, password);
        assertTrue(authToken.length() > 0);

        authService.createRole("Admin");
        authService.createRole("Support");
        authService.assignRole(username, "Admin");
        authService.assignRole(username, "Support");

        assertTrue(authService.allRoles(authToken).contains("Admin"));
        assertTrue(authService.allRoles(authToken).contains("Support"));
        assertTrue(authService.allRoles(authToken).size() == 2);
    }

    @Test
    void checkAllRoleWithInvalidToken() throws Exception {

        final String username = "User1";
        final String password = "aa093jl08";

        authService.createUser(username, password);
        authToken = authService.authenticate(username, password);
        assertTrue(authToken.length() > 0);

        authService.createRole("Admin");
        authService.createRole("Support");
        authService.assignRole(username, "Admin");
        authService.assignRole(username, "Support");

        assertTrue(authService.allRoles(authToken).contains("Admin"));
        assertTrue(authService.allRoles(authToken).contains("Support"));
        assertTrue(authService.allRoles(authToken).size() == 2);

        Exception e = assertThrows(AuthServiceException.class, () -> {
            authService.allRoles("abc");
        });

        assertTrue(e.getMessage().contains("Token is invalid"));
    }
}