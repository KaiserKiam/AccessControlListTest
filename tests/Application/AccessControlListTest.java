package Application;

import Presentation.SubsystemEnums;
import Presentation.SubsystemRoles;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.lang.reflect.Field;

/**
 * JUnit 5 test suite for the {@link AccessControlList} class.
 *
 * <p>This class provides comprehensive black-box unit testing of all public
 * methods in {@code AccessControlList}, covering normal inputs, edge cases,
 * boundary conditions, duplicate records, and configuration behavior. Test
 * cases map directly to the test procedure defined in
 * PWMS-ACS-TEST-PROC-001.</p>
 *
 * <p>Tests are executed in a fixed order using {@link MethodOrderer.OrderAnnotation}
 * because several test cases depend on state established by prior tests
 * (e.g., TC-002 requires the user added in TC-001). Tests that require an
 * isolated environment reset the Singleton and delete data files explicitly
 * before running.</p>
 *
 * <p><b>Singleton Reset:</b> Because {@code AccessControlList} uses the
 * Singleton pattern, {@link #resetSingleton()} uses Java Reflection to set
 * the private static {@code cf} field to {@code null}, allowing a fresh
 * instance to be created when {@link AccessControlList#Instance()} is called
 * again. This is required for TC-016, TC-018, TC-020, TC-021, and TC-022.</p>
 *
 * <p><b>Known behavior documented in tests:</b></p>
 * <ul>
 *   <li>{@link #TC009_AttemptToDeleteSysAdmin()} — SysAdmin cannot be deleted
 *       because both {@code deleteUser} overloads advance the iterator past the
 *       first record before entering the deletion loop.</li>
 *   <li>{@link #TC011_FindExistingUserByUsername()} and
 *       {@link #TC012_FindNonExistingUserByUsername()} — {@code find(String)}
 *       depends on {@code getNumUsers()} having been called first to populate
 *       {@code sList}.</li>
 * </ul>
 *
 * @author William Kerr - Project Manager
 * @author Isaac Nunez - Test Manager
 * @author Jack Wagenheim - Software Configuration Management
 * @author Rana Yum - Software Quality Assurance
 *
 * @version 1.0
 *
 * @see AccessControlList
 * @see SubsystemEnums
 * @see SubsystemRoles
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AccessControlListTest {

    /** Shared {@code AccessControlList} instance used across all test cases. */
    private static AccessControlList acl;

    // ─── Helper Methods ────────────────────────────────────────────

    /**
     * Resets the {@code AccessControlList} Singleton by setting the private
     * static field {@code cf} to {@code null} via Java Reflection. This allows
     * a new instance to be created on the next call to
     * {@link AccessControlList#Instance()}, which is necessary for test cases
     * that require a completely fresh state (TC-016, TC-018, TC-020, TC-021,
     * TC-022).
     *
     * @throws Exception if the {@code cf} field cannot be accessed via
     *                   reflection
     */
    private static void resetSingleton() throws Exception {
        Field field = AccessControlList.class.getDeclaredField("cf");
        field.setAccessible(true);
        field.set(null, null);
    }

    /**
     * Deletes the default ACS data file ({@code ACS.dat}) and the custom data
     * file ({@code CustomACS.dat}) from the working directory if they exist.
     * Called before tests that require a clean file system state.
     */
    private static void deleteACSFile() {
        new File("ACS.dat").delete();
        new File("CustomACS.dat").delete();
    }

    // ─── Setup ─────────────────────────────────────────────────────

    /**
     * Initializes the test environment before any test cases are executed.
     * Deletes any existing ACS data files, resets the Singleton, and creates a
     * fresh {@code AccessControlList} instance initialized with only the default
     * SysAdmin record.
     *
     * @throws Exception if the Singleton reset via reflection fails
     */
    @BeforeAll
    static void setup() throws Exception {
        deleteACSFile();
        resetSingleton();
        acl = AccessControlList.Instance();
    }

    // ─── addUser() Tests ───────────────────────────────────────────

    /**
     * TC-001: Verifies that a new user can be added with valid credentials.
     *
     * <p>Calls {@code addUser()} with a valid username, password, subsystem,
     * and role, then verifies the record exists using
     * {@code find(String, String, SubsystemEnums, SubsystemRoles)}.</p>
     *
     * <p><b>Expected:</b> {@code find()} returns {@code true} for the added
     * record.</p>
     */
    @Test
    @Order(1)
    void TC001_AddValidUser() {
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        assertTrue(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
    }

    /**
     * TC-002: Verifies that a duplicate user record is not added.
     *
     * <p>Attempts to add a record identical to the one added in TC-001.
     * The user count before and after the duplicate add attempt must be
     * equal.</p>
     *
     * <p><b>Precondition:</b> "TestUser1" already exists from TC-001.</p>
     * <p><b>Expected:</b> {@code getNumUsers()} returns the same count before
     * and after the duplicate add.</p>
     */
    @Test
    @Order(2)
    void TC002_AddDuplicateUser() {
        int countBefore = acl.getNumUsers();
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        int countAfter = acl.getNumUsers();
        assertEquals(countBefore, countAfter);
    }

    /**
     * TC-003: Verifies behavior when a null username is provided to
     * {@code addUser()}.
     *
     * <p>A {@code null} username causes a {@code NullPointerException} during
     * the {@code writeRecord()} call when {@code writeUTF(null)} is attempted
     * on the {@code DataOutputStream}.</p>
     *
     * <p><b>Expected:</b> An exception is thrown; no record is added.</p>
     */
    @Test
    @Order(3)
    void TC003_AddUserWithNullUsername() {
        assertThrows(Exception.class, () -> {
            acl.addUser(null, "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        });
    }

    /**
     * TC-004: Verifies that a user can be added with an empty string password.
     *
     * <p>The system performs no password validation, so an empty string is
     * treated as a valid password value.</p>
     *
     * <p><b>Expected:</b> {@code find()} returns {@code true} for the record
     * with an empty password.</p>
     */
    @Test
    @Order(4)
    void TC004_AddUserWithEmptyPassword() {
        acl.addUser("TestUser2", "", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        assertTrue(acl.find("TestUser2", "", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    /**
     * TC-005: Verifies that the same username can hold multiple role records.
     *
     * <p>Adds a second record for "TestUser1" with a different role and
     * password. Uniqueness is enforced on the full four-field combination, not
     * on username alone, so both records should coexist. The unique user count
     * should remain 2 (TestUser1 and TestUser2 from TC-004).</p>
     *
     * <p><b>Precondition:</b> "TestUser1" exists as DATAANALYST from TC-001.</p>
     * <p><b>Expected:</b> {@code getNumUsers()} returns 2; both role records
     * are findable by full credentials.</p>
     */
    @Test
    @Order(5)
    void TC005_AddSameUsernameWithDifferentRole() {
        acl.addUser("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        int count = acl.getNumUsers();
        assertEquals(2, count);
        assertTrue(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        assertTrue(acl.find("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    // ─── deleteUser() Tests ────────────────────────────────────────

    /**
     * TC-006: Verifies that an existing user can be deleted by username only.
     *
     * <p>All records associated with "TestUser1" (including multiple roles) are
     * removed. The user count decreases and {@code find(String)} returns
     * {@code false} after deletion.</p>
     *
     * <p><b>Precondition:</b> "TestUser1" exists from prior tests.</p>
     * <p><b>Expected:</b> {@code find("TestUser1")} returns {@code false};
     * user count is lower than before deletion.</p>
     */
    @Test
    @Order(6)
    void TC006_DeleteExistingUserByUsername() {
        int countBefore = acl.getNumUsers();
        acl.deleteUser("TestUser1");
        acl.getNumUsers(); // refresh sList
        assertFalse(acl.find("TestUser1"));
        assertTrue(acl.getNumUsers() < countBefore);
    }

    /**
     * TC-007: Verifies that deleting a non-existing user does not throw an
     * exception and does not modify the user count.
     *
     * <p><b>Precondition:</b> "NonExistentUser" does not exist in the system.</p>
     * <p><b>Expected:</b> No exception is thrown; {@code getNumUsers()} returns
     * the same value before and after the call.</p>
     */
    @Test
    @Order(7)
    void TC007_DeleteNonExistingUser() {
        int countBefore = acl.getNumUsers();
        assertDoesNotThrow(() -> acl.deleteUser("NonExistentUser"));
        assertEquals(countBefore, acl.getNumUsers());
    }

    /**
     * TC-008: Verifies that deleting a user by full credentials removes only
     * the matching role record and leaves other records for the same username
     * intact.
     *
     * <p>"TestUser1" is added with two roles. Only the DATAANALYST record is
     * deleted using the four-argument {@code deleteUser()} overload. The AUDITOR
     * record must remain.</p>
     *
     * <p><b>Expected:</b> DATAANALYST record not found; AUDITOR record still
     * found.</p>
     */
    @Test
    @Order(8)
    void TC008_DeleteUserWithFullCredentials() {
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.deleteUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        assertFalse(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        assertTrue(acl.find("TestUser1", "differentPass", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    /**
     * TC-009: Verifies that the SysAdmin record cannot be deleted.
     *
     * <p>This test documents a known code behavior: both {@code deleteUser()}
     * overloads call {@code itr.next()} before entering the while loop,
     * unconditionally skipping the first record in {@code aList}. Since
     * SysAdmin is always the first record, it is protected from deletion.</p>
     *
     * <p><b>Expected:</b> {@code find("SysAdmin", "SAPass", ...)} returns
     * {@code true} after the delete attempt.</p>
     */
    @Test
    @Order(9)
    void TC009_AttemptToDeleteSysAdmin() {
        acl.deleteUser("SysAdmin");
        assertTrue(acl.find("SysAdmin", "SAPass", SubsystemEnums.ACS, SubsystemRoles.SYSTEMADMIN));
    }

    /**
     * TC-010: Verifies that the last record in the list can be deleted without
     * errors.
     *
     * <p>Several users are added sequentially. "LastUser" is added as the final
     * record. After deletion, "LastUser" must not be found and all previously
     * added users must remain unaffected.</p>
     *
     * <p><b>Expected:</b> "LastUser" not found; no exceptions thrown; User_A
     * and User_B still present.</p>
     */
    @Test
    @Order(10)
    void TC010_DeleteLastUserInList() {
        acl.addUser("User_A", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("User_B", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("LastUser", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        assertDoesNotThrow(() -> acl.deleteUser("LastUser"));
        assertFalse(acl.find("LastUser", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        assertTrue(acl.find("User_A", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
        assertTrue(acl.find("User_B", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR));
    }

    // ─── find() Tests ──────────────────────────────────────────────

    /**
     * TC-011: Verifies that {@code find(String)} returns {@code true} for an
     * existing username.
     *
     * <p>{@code getNumUsers()} is called before {@code find(String)} to
     * populate {@code sList}, which is required for {@code find(String)} to
     * function correctly.</p>
     *
     * <p><b>Expected:</b> Returns {@code true} for "TestUser1".</p>
     */
    @Test
    @Order(11)
    void TC011_FindExistingUserByUsername() {
        acl.addUser("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.getNumUsers(); // populate sList first
        assertTrue(acl.find("TestUser1"));
    }

    /**
     * TC-012: Verifies that {@code find(String)} returns {@code false} for a
     * username that does not exist in the system.
     *
     * <p>{@code getNumUsers()} is called before {@code find(String)} to
     * populate {@code sList}.</p>
     *
     * <p><b>Expected:</b> Returns {@code false} for "GhostUser".</p>
     */
    @Test
    @Order(12)
    void TC012_FindNonExistingUserByUsername() {
        acl.getNumUsers(); // populate sList first
        assertFalse(acl.find("GhostUser"));
    }

    /**
     * TC-013: Verifies that {@code find(String, String, SubsystemEnums,
     * SubsystemRoles)} returns {@code true} when all four credentials match
     * an existing record exactly.
     *
     * <p>This overload searches {@code aList} directly and does not depend on
     * {@code sList} or a prior call to {@code getNumUsers()}.</p>
     *
     * <p><b>Expected:</b> Returns {@code true}.</p>
     */
    @Test
    @Order(13)
    void TC013_FindWithCorrectFullCredentials() {
        assertTrue(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
    }

    /**
     * TC-014: Verifies that {@code find(String, String, SubsystemEnums,
     * SubsystemRoles)} returns {@code false} when the password does not match.
     *
     * <p>All fields are correct except the password, which is intentionally
     * wrong. A partial match must not return {@code true}.</p>
     *
     * <p><b>Expected:</b> Returns {@code false}.</p>
     */
    @Test
    @Order(14)
    void TC014_FindWithWrongPassword() {
        assertFalse(acl.find("TestUser1", "wrongPassword", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST));
    }

    /**
     * TC-015: Verifies that {@code find(String, String, SubsystemEnums,
     * SubsystemRoles)} returns {@code false} when the role does not match.
     *
     * <p>"TestUser1" is registered as DATAANALYST. Searching with AUDITOR must
     * not produce a match even if all other fields are correct.</p>
     *
     * <p><b>Expected:</b> Returns {@code false}.</p>
     */
    @Test
    @Order(15)
    void TC015_FindWithWrongRole() {
        assertFalse(acl.find("TestUser1", "password123", SubsystemEnums.DAS, SubsystemRoles.AUDITOR));
    }

    // ─── getNumUsers() Tests ───────────────────────────────────────

    /**
     * TC-016: Verifies that {@code getNumUsers()} returns 0 when only the
     * default SysAdmin record exists.
     *
     * <p>The Singleton is reset and all data files are deleted to ensure a
     * clean initial state. SysAdmin is skipped by the iterator logic in
     * {@code getNumUsers()}, so the count must be 0.</p>
     *
     * <p><b>Expected:</b> Returns {@code 0}.</p>
     *
     * @throws Exception if the Singleton reset via reflection fails
     */
    @Test
    @Order(16)
    void TC016_GetUserCountWithOnlySysAdmin() throws Exception {
        deleteACSFile();
        resetSingleton();
        acl = AccessControlList.Instance();
        assertEquals(0, acl.getNumUsers());
    }

    /**
     * TC-017: Verifies that {@code getNumUsers()} returns an accurate count
     * when multiple distinct users exist.
     *
     * <p>Three users with different usernames are added after the fresh instance
     * from TC-016.</p>
     *
     * <p><b>Expected:</b> Returns {@code 3}.</p>
     */
    @Test
    @Order(17)
    void TC017_GetUserCountWithMultipleUsers() {
        acl.addUser("User1", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("User2", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("User3", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAGATHERER);
        assertEquals(3, acl.getNumUsers());
    }

    /**
     * TC-018: Verifies that {@code getNumUsers()} counts the same username only
     * once, regardless of how many role records it has.
     *
     * <p>"MultiRole" is added three times with different roles. The unique user
     * count must be 1, not 3.</p>
     *
     * <p><b>Expected:</b> Returns {@code 1}.</p>
     *
     * @throws Exception if the Singleton reset via reflection fails
     */
    @Test
    @Order(18)
    void TC018_GetUserCountWithDuplicateUsernames() throws Exception {
        deleteACSFile();
        resetSingleton();
        acl = AccessControlList.Instance();
        acl.addUser("MultiRole", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("MultiRole", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("MultiRole", "pass3", SubsystemEnums.AAS, SubsystemRoles.WATCHMAN);
        assertEquals(1, acl.getNumUsers());
    }

    // ─── Configuration Method Tests ────────────────────────────────

    /**
     * TC-019: Verifies that {@code Instance()} returns the same object
     * reference on every call, confirming the Singleton design pattern.
     *
     * <p>{@code Instance()} is called twice and the references are compared
     * using {@code assertSame()}, which checks object identity rather than
     * equality.</p>
     *
     * <p><b>Expected:</b> Both references point to the same instance.</p>
     */
    @Test
    @Order(19)
    void TC019_SingletonInstanceVerification() {
        AccessControlList ref1 = AccessControlList.Instance();
        AccessControlList ref2 = AccessControlList.Instance();
        assertSame(ref1, ref2);
    }

    /**
     * TC-020: Verifies that {@code chgSAPass()} changes the System
     * Administrator password used when a new ACS file is created.
     *
     * <p>{@code chgSAPass()} is called before {@link AccessControlList#Instance()}
     * to ensure the new password is written to the SysAdmin record during file
     * initialization. The test verifies the change by searching for SysAdmin
     * with the new password.</p>
     *
     * <p><b>Expected:</b> {@code find()} returns {@code true} for SysAdmin with
     * "newSAPassword".</p>
     *
     * @throws Exception if the Singleton reset via reflection fails
     */
    @Test
    @Order(20)
    void TC020_ChangeSystemAdminPassword() throws Exception {
        deleteACSFile();
        resetSingleton();
        AccessControlList.chgSAPass("newSAPassword");
        acl = AccessControlList.Instance();
        assertTrue(acl.find("SysAdmin", "newSAPassword", SubsystemEnums.ACS, SubsystemRoles.SYSTEMADMIN));
    }

    /**
     * TC-021: Verifies that {@code chgFilename()} changes the data file used
     * for ACS storage.
     *
     * <p>{@code chgFilename()} is called before {@link AccessControlList#Instance()}
     * to redirect all file operations to "CustomACS.dat". After adding a user,
     * the test confirms that "CustomACS.dat" exists and "ACS.dat" does not.</p>
     *
     * <p><b>Expected:</b> "CustomACS.dat" exists; "ACS.dat" does not exist.</p>
     *
     * @throws Exception if the Singleton reset via reflection fails
     */
    @Test
    @Order(21)
    void TC021_ChangeACSFilename() throws Exception {
        deleteACSFile();
        resetSingleton();
        AccessControlList.chgSAPass("SAPass"); // reset from TC-020
        AccessControlList.chgFilename("CustomACS.dat");
        acl = AccessControlList.Instance();
        acl.addUser("FileTestUser", "pass", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        assertTrue(new File("CustomACS.dat").exists());
        assertFalse(new File("ACS.dat").exists());
    }

    // ─── Utility Method Tests ──────────────────────────────────────

    /**
     * TC-022: Verifies that {@code dump()} executes without throwing an
     * exception and prints all records to standard output.
     *
     * <p>A fresh instance is created with three known user records. Since
     * {@code dump()} writes to standard output rather than returning a value,
     * correctness of the console output must be verified manually. This test
     * confirms the method completes without error.</p>
     *
     * <p><b>Expected:</b> No exception is thrown during {@code dump()}.</p>
     *
     * @throws Exception if the Singleton reset via reflection fails
     */
    @Test
    @Order(22)
    void TC022_DumpAllRecords() throws Exception {
        new File("CustomACS.dat").delete();
        resetSingleton();
        AccessControlList.chgFilename("ACS.dat");
        acl = AccessControlList.Instance();
        acl.addUser("DumpUser1", "pass1", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);
        acl.addUser("DumpUser2", "pass2", SubsystemEnums.AAS, SubsystemRoles.AUDITOR);
        acl.addUser("DumpUser3", "pass3", SubsystemEnums.DAS, SubsystemRoles.DATAGATHERER);
        assertDoesNotThrow(() -> acl.dump());
    }

    // ─── Cleanup ───────────────────────────────────────────────────

    /**
     * Removes all ACS data files created during the test run after all test
     * cases have completed. Ensures no residual files remain in the working
     * directory after the suite finishes.
     */
    @AfterAll
    static void cleanup() {
        new File("ACS.dat").delete();
        new File("CustomACS.dat").delete();
    }
}