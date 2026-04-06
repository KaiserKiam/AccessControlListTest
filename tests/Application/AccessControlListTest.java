package Application;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.lang.reflect.Field;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AccessControlListTest {

    private static AccessControlList acl;

    // ─── Helper: Reset Singleton ───────────────────────────────────
    private static void resetSingleton() throws Exception {
        Field field = AccessControlList.class.getDeclaredField("cf");
        field.setAccessible(true);
        field.set(null, null);
    }

    private static void deleteACSFile() {
        new File("ACS.dat").delete();
        new File("CustomACS.dat").delete();
    }

    // ─── Setup ─────────────────────────────────────────────────────
    @BeforeAll
    static void setup() throws Exception {
        deleteACSFile();
        resetSingleton();
        acl = AccessControlList.Instance();
    }

    // ─── addUser() Tests ───────────────────────────────────────────

    @Test
    @Order(1)
    void TC001_AddValidUser() {
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        assertTrue(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
    }

    @Test
    @Order(2)
    void TC002_AddDuplicateUser() {
        // TestUser1 already added in TC-001
        int countBefore = acl.getNumUsers();
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        int countAfter = acl.getNumUsers();
        assertEquals(countBefore, countAfter);
    }

    @Test
    @Order(3)
    void TC003_AddUserWithNullUsername() {
        // Null username causes NullPointerException during writeRecord()
        assertThrows(Exception.class, () -> {
            acl.addUser(null, "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        });
    }

    @Test
    @Order(4)
    void TC004_AddUserWithEmptyPassword() {
        acl.addUser("TestUser2", "", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        assertTrue(acl.find("TestUser2", "", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    @Test
    @Order(5)
    void TC005_AddSameUsernameWithDifferentRole() {
        // TestUser1 exists as DATAANALYST; add same username with AUDITOR role
        acl.addUser("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        int count = acl.getNumUsers();
        // TestUser1 should still count as 1 unique user
        // TestUser2 from TC-004 also exists, so expect 2
        assertEquals(2, count);
        // Both role records should be findable by full credentials
        assertTrue(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        assertTrue(acl.find("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    // ─── deleteUser() Tests ────────────────────────────────────────

    @Test
    @Order(6)
    void TC006_DeleteExistingUserByUsername() {
        // TestUser1 exists from prior tests
        int countBefore = acl.getNumUsers();
        acl.deleteUser("TestUser1");
        acl.getNumUsers(); // refresh sList
        assertFalse(acl.find("TestUser1"));
        assertTrue(acl.getNumUsers() < countBefore);
    }

    @Test
    @Order(7)
    void TC007_DeleteNonExistingUser() {
        int countBefore = acl.getNumUsers();
        assertDoesNotThrow(() -> acl.deleteUser("NonExistentUser"));
        assertEquals(countBefore, acl.getNumUsers());
    }

    @Test
    @Order(8)
    void TC008_DeleteUserWithFullCredentials() {
        // Add TestUser1 back with two roles
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        // Delete only the DATAANALYST record
        acl.deleteUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        // DATAANALYST record should be gone
        assertFalse(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        // AUDITOR record should still exist
        assertTrue(acl.find("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    @Test
    @Order(9)
    void TC009_AttemptToDeleteSysAdmin() {
        // SysAdmin is the first record; iterator.next() skips it before the loop
        acl.deleteUser("SysAdmin");
        // SysAdmin should still exist
        assertTrue(acl.find("SysAdmin", "SAPass", SubsystemEnums.ACS, SubsystemRoles.SYSTEMADMIN));
    }

    @Test
    @Order(10)
    void TC010_DeleteLastUserInList() {
        acl.addUser("User_A", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("User_B", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("LastUser", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        assertDoesNotThrow(() -> acl.deleteUser("LastUser"));
        assertFalse(acl.find("LastUser", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        // Other users should be unaffected
        assertTrue(acl.find("User_A", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        assertTrue(acl.find("User_B", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    // ─── find() Tests ──────────────────────────────────────────────

    @Test
    @Order(11)
    void TC011_FindExistingUserByUsername() {
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        // getNumUsers() must be called first to populate sList used by find(String)
        acl.getNumUsers();
        assertTrue(acl.find("TestUser1"));
    }

    @Test
    @Order(12)
    void TC012_FindNonExistingUserByUsername() {
        // getNumUsers() must be called first to populate sList used by find(String)
        acl.getNumUsers();
        assertFalse(acl.find("GhostUser"));
    }

    @Test
    @Order(13)
    void TC013_FindWithCorrectFullCredentials() {
        // Uses aList directly, no need to call getNumUsers() first
        assertTrue(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
    }

    @Test
    @Order(14)
    void TC014_FindWithWrongPassword() {
        assertFalse(acl.find("TestUser1", "wrongPassword", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
    }

    @Test
    @Order(15)
    void TC015_FindWithWrongRole() {
        // TestUser1 is DATAANALYST, not AUDITOR
        assertFalse(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.AUDITOR));
    }

    // ─── getNumUsers() Tests ───────────────────────────────────────

    @Test
    @Order(16)
    void TC016_GetUserCountWithOnlySysAdmin() throws Exception {
        // Requires completely fresh state
        deleteACSFile();
        resetSingleton();
        acl = AccessControlList.Instance();
        // SysAdmin is skipped by iterator logic, so count should be 0
        assertEquals(0, acl.getNumUsers());
    }

    @Test
    @Order(17)
    void TC017_GetUserCountWithMultipleUsers() {
        acl.addUser("User1", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("User2", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("User3", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAGATHERER);
        assertEquals(3, acl.getNumUsers());
    }

    @Test
    @Order(18)
    void TC018_GetUserCountWithDuplicateUsernames() throws Exception {
        // Fresh state to isolate this test
        deleteACSFile();
        resetSingleton();
        acl = AccessControlList.Instance();
        acl.addUser("MultiRole", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("MultiRole", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("MultiRole", "pass3", SubsystemEnums.AAS, SubsystemRoles.WATCHMAN);
        // Same username across 3 records should count as 1 unique user
        assertEquals(1, acl.getNumUsers());
    }

    // ─── Configuration Method Tests ────────────────────────────────

    @Test
    @Order(19)
    void TC019_SingletonInstanceVerification() {
        AccessControlList ref1 = AccessControlList.Instance();
        AccessControlList ref2 = AccessControlList.Instance();
        assertSame(ref1, ref2);
    }

    @Test
    @Order(20)
    void TC020_ChangeSystemAdminPassword() throws Exception {
        // chgSAPass() must be called before Instance()
        deleteACSFile();
        resetSingleton();
        AccessControlList.chgSAPass("newSAPassword");
        acl = AccessControlList.Instance();
        // SysAdmin record should now use the new password
        assertTrue(acl.find("SysAdmin", "newSAPassword", SubsystemEnums.ACS, SubsystemRoles.SYSTEMADMIN));
    }

    @Test
    @Order(21)
    void TC021_ChangeACSFilename() throws Exception {
        // chgFilename() must be called before Instance()
        deleteACSFile();
        resetSingleton();
        // Reset SAPassword back to default since TC-020 changed it
        AccessControlList.chgSAPass("SAPass");
        AccessControlList.chgFilename("CustomACS.dat");
        acl = AccessControlList.Instance();
        acl.addUser("FileTestUser", "pass", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        // CustomACS.dat should exist, ACS.dat should not
        assertTrue(new File("CustomACS.dat").exists());
        assertFalse(new File("ACS.dat").exists());
    }

    // ─── Utility Method Tests ──────────────────────────────────────

    @Test
    @Order(22)
    void TC022_DumpAllRecords() throws Exception {
        // Fresh state with known records
        new File("CustomACS.dat").delete();
        resetSingleton();
        AccessControlList.chgFilename("ACS.dat");
        acl = AccessControlList.Instance();
        acl.addUser("DumpUser1", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("DumpUser2", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("DumpUser3", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAGATHERER);
        // dump() prints to console - verify it runs without exception
        assertDoesNotThrow(() -> acl.dump());
    }

    // ─── Cleanup ───────────────────────────────────────────────────

    @AfterAll
    static void cleanup() {
        new File("ACS.dat").delete();
        new File("CustomACS.dat").delete();
    }
}