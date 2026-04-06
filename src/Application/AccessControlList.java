package Application;

import Presentation.*;

import java.util.*;
import java.io.*;
import java.nio.file.*;

/**
 * Manages user authentication and access control for the Predictive Wastewater
 * Management System (PWMS). This class maintains a persistent list of user
 * records, each associated with a username, password, subsystem, and role.
 *
 * <p>AccessControlList is implemented as a Singleton — only one instance may
 * exist at runtime. The instance is initialized by calling {@link #Instance()},
 * which reads from or creates the ACS data file on first invocation.</p>
 *
 * <p>The default data file is {@code ACS.dat}. The default System Administrator
 * credentials are username {@code SysAdmin} with password {@code SAPass},
 * subsystem {@code ACS}, and role {@code SYSTEMADMIN}.</p>
 *
 * <p><b>Configuration methods must be called before the first call to
 * {@link #Instance()}:</b></p>
 * <ul>
 *   <li>{@link #chgSAPass(String)} — change the System Administrator password</li>
 *   <li>{@link #chgFilename(String)} — change the ACS data file name</li>
 * </ul>
 *
 * <p><b>Note:</b> {@link #find(String)} depends on {@link #getNumUsers()} having
 * been called first to populate the internal username list ({@code sList}).
 * Use {@link #find(String, String, SubsystemEnums, SubsystemRoles)} for
 * credential-based lookups without this dependency.</p>
 *
 * <p><b>Known behavior:</b> The first record in the list (SysAdmin) is protected
 * from deletion. Both {@code deleteUser} overloads advance the iterator past the
 * first record before entering the deletion loop.</p>
 *
 * @author William Kerr - Project Manager
 * @author Isaac Nunez - Test Manager
 * @author Jack Wagenheim - Software Configuration Management
 * @author Rana Yum - Software Quality Assurance
 *
 * @version 1.0
 *
 * @see SubsystemEnums
 * @see SubsystemRoles
 */
public class AccessControlList
{
   private static final boolean DBG =    false;
   private static String ACSFile =   "ACS.dat";
   private static AccessControlList cf  = null;
   private DataInputStream  dis         = null;
   private DataOutputStream dos         = null;
   private static String SAPassword = "SAPass";
   private static File                    file;
   private static FileOutputStream  fos = null;
   private static FileInputStream   fis = null;

   private final ArrayList<ACSRecord> aList;
   private final ArrayList<String>    sList;


   /**
    * Sets the System Administrator password used when creating a new ACS data
    * file. This method must be called before the first invocation of
    * {@link #Instance()}. If called after the instance has been created, the
    * change will have no effect on the existing file or in-memory records.
    *
    * @param pW the new System Administrator password; must not be {@code null}
    */
   public static void chgSAPass(String pW)
   {
      SAPassword = pW;
   }

   /**
    * Sets the file name used for reading and writing ACS data. This method must
    * be called before the first invocation of {@link #Instance()}. If called
    * after the instance has been created, the change will have no effect.
    *
    * @param fN the new file name for the ACS data file (e.g., {@code "CustomACS.dat"});
    *           must not be {@code null}
    */
   public static void chgFilename(String fN)
   {
      ACSFile = fN;
   }

   /**
    * Returns the single instance of AccessControlList, creating it if it does
    * not yet exist. On first call, the constructor reads the ACS data file if it
    * exists, or creates a new file initialized with the default SysAdmin record.
    *
    * <p>This method implements the Singleton design pattern. All subsequent calls
    * return the same instance created on the first invocation.</p>
    *
    * @return the single shared instance of {@code AccessControlList}
    */
   public static AccessControlList Instance()
   {
      if (cf == null) cf = new AccessControlList();
      return cf;
   }

   /**
    * Represents a single access control record associating a user with a
    * subsystem and role. Records are stored in the ACS data file and held
    * in memory within the {@code aList} of the enclosing
    * {@code AccessControlList}.
    *
    * <p>Two {@code ACSRecord} objects are considered equal if and only if all
    * four fields — username, password, subsystem, and role — match exactly.</p>
    */
   private class ACSRecord
   {

      /** The username associated with this record. */
      final private String userName;

      /** The password associated with this record. */
      final private String password;

      /** The subsystem this record grants access to. */
      final private SubsystemEnums subsys;

      /** The role assigned to the user within the subsystem. */
      final private SubsystemRoles subrol;

      /**
       * Constructs a new ACSRecord with the specified credentials and access
       * details.
       *
       * @param uName the username for this record; must not be {@code null}
       * @param pw    the password for this record
       * @param se    the subsystem this record is associated with
       * @param sr    the role assigned within the subsystem
       */
      private ACSRecord
      (
         String uName,
         String pw,
         SubsystemEnums se,
         SubsystemRoles sr)
      {
         userName = uName;
         password =    pw;
         subsys   =    se;
         subrol   =    sr;
      }

      /**
       * Compares this record to another {@code ACSRecord} for equality. All four
       * fields must match: username, password, subsystem, and role.
       *
       * @param a the {@code ACSRecord} to compare against
       * @return {@code true} if all fields are equal; {@code false} otherwise
       */
      public boolean equals(ACSRecord a)
      {
         if ( (a.getUserName().equals(userName) == false) ||
              (a.getPassword().equals(password) == false) ||
              (a.getRole()     != subrol)   ||
              (a.getSubsys()   != subsys) )
            return false;
         else
            return true;
      }

      /**
       * Returns the username for this record.
       *
       * @return the username string
       */
      public String getUserName()
         { return userName; }

      /**
       * Returns the password for this record.
       *
       * @return the password string
       */
      public String getPassword()
         { return password; }

      /**
       * Returns the subsystem associated with this record.
       *
       * @return the {@link SubsystemEnums} value
       */
      public SubsystemEnums getSubsys()
         { return subsys;   }

      /**
       * Returns the role assigned in this record.
       *
       * @return the {@link SubsystemRoles} value
       */
      public SubsystemRoles getRole()
         { return subrol;       }

   }

   /**
    * Private constructor for the Singleton pattern. Initializes the in-memory
    * record lists and reads the ACS data file. If the file does not exist, a new
    * file is created with a default SysAdmin record.
    */
   private AccessControlList()
   {
      aList     = new ArrayList<>();
      sList     = new ArrayList<>();
      file      = new File(ACSFile);
      //
      // Read the ACS file.
      //
      readACSFile();
   }

   /**
    * Writes a single {@code ACSRecord} to the currently open
    * {@code DataOutputStream}. Fields are written in the following order:
    * username (UTF), password (UTF), subsystem ordinal (int), role ordinal (int).
    *
    * <p>If a write error occurs, a stack trace is printed and the application
    * exits.</p>
    *
    * @param aR the {@code ACSRecord} to write; must not be {@code null}
    */
   private void writeRecord(final ACSRecord aR)
   {
      try
      {
         dos.writeUTF(aR.getUserName());
         dos.writeUTF(aR.getPassword());
         int i1 = aR.getSubsys().ordinal();
         dos.writeInt(i1);
         i1     = aR.getRole().ordinal();
         dos.writeInt(i1);
      }
      catch (Exception e)
      {
         System.out.print("Unable to write to: ");
         System.out.println(ACSFile);
         e.printStackTrace();
         System.exit(0);
      }
   }

   /**
    * Overwrites the ACS data file with all records currently held in
    * {@code aList}. The existing file is deleted before writing. This method is
    * called after any deletion operation to ensure the file stays synchronized
    * with in-memory state.
    */
   private void writeListToFile()
   {
      file.delete();
      try
      {
         fos = new FileOutputStream(ACSFile);
         dos = new DataOutputStream(fos);
         for (ACSRecord a : aList)
         {
            writeRecord(a);
         }
         dos.flush();
         fos.close();
      }
      catch (Exception e)
      {
         e.printStackTrace();
      }
   }

   /**
    * Creates a new ACS data file and initializes it with a single SysAdmin
    * record using the current value of {@link #SAPassword}. This method is
    * called by {@link #readACSFile()} when no existing data file is found.
    */
   private void createNewFile()
   {
      ACSRecord aR = new ACSRecord
      (
         "SysAdmin",
         SAPassword,
         SubsystemEnums.ACS,
         SubsystemRoles.SYSTEMADMIN
      );
      aList.clear();
      try
      {
         fos = new FileOutputStream(ACSFile,true);
         dos = new DataOutputStream(fos);
         writeRecord(aR);
         aList.add(aR);
         dos.flush();
         fos.close();
      }
      catch (Exception e)
      {
         e.printStackTrace();
      }
   }

   /**
    * Reads a single {@code ACSRecord} from the currently open
    * {@code DataInputStream}. Fields are read in the following order: username
    * (UTF), password (UTF), subsystem ordinal (int), role ordinal (int).
    *
    * @return the {@code ACSRecord} read from the stream, or {@code null} if the
    *         end of the stream has been reached or an {@code IOException} occurs
    */
   private ACSRecord readRecord()
   {
      ACSRecord asr = null;
      try
      {
         final String uN = dis.readUTF();
         if (uN == null) return null;
         final String pw = dis.readUTF();
         final int i1 = dis.readInt();
         final SubsystemEnums se =
               SubsystemEnums.values()[i1];
         final int i2 = dis.readInt();
         final SubsystemRoles sr =
               SubsystemRoles.values()[i2];
         asr = new ACSRecord(uN, pw, se, sr);
         if (DBG) System.out.println
               ("Uname: " + uN + ", PW: " + pw);
         if (DBG) System.out.println
               ("Subsys: " + se + ", Role: " + sr);
      }
      catch (IOException e)
      {
         return null;
      }
      return asr;
   }

   /**
    * Reads all records from the ACS data file into {@code aList}. If the file
    * does not exist, {@link #createNewFile()} is called to initialize a new file
    * with the default SysAdmin record. The file stream is closed after reading
    * via {@link #closeFile()}.
    */
   private void readACSFile()
   {

      if (file.exists())
      {
         try
         {
            fis = new FileInputStream(ACSFile);
            dis = new DataInputStream    (fis);
         }
         catch (Exception e)
         {
            e.printStackTrace();
         }
         aList.clear();
         ACSRecord rr = readRecord();
         while (rr != null) {
            aList.add(rr);
            rr = readRecord();
         }

      }
      else
         createNewFile();

      closeFile();

   }

   /**
    * Prints all records currently held in {@code aList} to standard output.
    * Each record is displayed on two lines:
    * <pre>
    * Uname: [username], PW: [password]
    * Subsys: [subsystem], Role: [role]
    * </pre>
    * This method is intended for debugging and verification purposes.
    */
   public void dump()
   {
      System.out.println("DUMP:");
      for (ACSRecord a: aList)
      {
         final String uN = a.getUserName();
         final String pw = a.getPassword();
         final SubsystemRoles sr = a.getRole();
         final SubsystemEnums se = a.getSubsys();
         System.out.println
               ("Uname: " + uN + ", PW: " + pw);
         System.out.println
               ("Subsys: " + se + ", Role: " + sr);

      }
   }

   /**
    * Closes the current {@code DataInputStream} if one is open. Called after
    * file read operations to release the file handle.
    */
   private void closeFile()
   {
      try
      {
         if (dis != null) dis.close();
      }
      catch (IOException e)
      {
         e.printStackTrace();
      }
   }

   /**
    * Returns whether a user with the given username exists in the internal
    * username list ({@code sList}).
    *
    * <p><b>Important:</b> {@code sList} is only populated when
    * {@link #getNumUsers()} is called. This method will return {@code false} for
    * any username if {@code getNumUsers()} has not been called at least once
    * prior. For a lookup that does not depend on {@code sList}, use
    * {@link #find(String, String, SubsystemEnums, SubsystemRoles)} instead.</p>
    *
    * @param uName the username to search for
    * @return {@code true} if the username is found in {@code sList};
    *         {@code false} otherwise
    */
   public boolean find
   (
       String uName
   )
   {
      for (String s : sList)
         if (s.equals(uName)) return true;
      return false;
   }

   /**
    * Returns whether a record matching all four credentials exists in
    * {@code aList}. All fields — username, password, subsystem, and role — must
    * match exactly for the method to return {@code true}.
    *
    * <p>This method does not depend on {@link #getNumUsers()} having been called
    * first and searches {@code aList} directly.</p>
    *
    * @param uName    the username to search for
    * @param password the password to match
    * @param se       the subsystem to match
    * @param sr       the role to match
    * @return {@code true} if a matching record is found; {@code false} otherwise
    */
   public boolean find
   (
      String uName,
      String password,
      SubsystemEnums se,
      SubsystemRoles sr
   )
   {
      ACSRecord b = new ACSRecord(uName,password,se,sr);
      for (ACSRecord a : aList)
         if (a.equals(b)) return true;
      return false;
   }

   /**
    * Removes the record matching all four credentials from both {@code aList}
    * and the ACS data file. Only the specific record matching the exact
    * username, password, subsystem, and role combination is removed. Other
    * records for the same username with different roles are unaffected.
    *
    * <p><b>Note:</b> The first record in {@code aList} (SysAdmin) is never
    * evaluated for deletion. The iterator is advanced past the first element
    * before the loop begins, making SysAdmin undeletable via this method.</p>
    *
    * @param uName    the username of the record to delete
    * @param password the password of the record to delete
    * @param se       the subsystem of the record to delete
    * @param sr       the role of the record to delete
    */
   public void deleteUser
   (
      String uName,
      String password,
      SubsystemEnums se,
      SubsystemRoles sr
   )
   {
      ACSRecord  acR = new ACSRecord(uName,password,se,sr);
      Iterator itr = aList.iterator();
      itr.next();

      while (itr.hasNext())
      {
         final ACSRecord a = (ACSRecord) itr.next();
         if (acR.equals(a))
            itr.remove();
      }
      writeListToFile();
   }

   /**
    * Removes all records matching the given username from both {@code aList} and
    * the ACS data file. If the username has multiple role records, all of them
    * are removed. If no matching records are found, no changes are made.
    *
    * <p><b>Note:</b> The first record in {@code aList} (SysAdmin) is never
    * evaluated for deletion. The iterator is advanced past the first element
    * before the loop begins, making SysAdmin undeletable via this method.</p>
    *
    * @param uName the username whose records should be deleted
    */
   public void deleteUser(final String uName)
   {
      Iterator itr = aList.iterator();
      itr.next();

      while (itr.hasNext())
      {
         ACSRecord aR = (ACSRecord) itr.next();
         if (aR.getUserName().equals(uName))
            itr.remove();
      }
      writeListToFile();
   }

   /**
    * Adds a new user record with the specified credentials to both {@code aList}
    * and the ACS data file. If an identical record already exists (same username,
    * password, subsystem, and role), the record is not added and the method
    * returns silently.
    *
    * <p>A user may have multiple records with the same username if the
    * subsystem, role, or password differ. Uniqueness is enforced on the full
    * four-field combination, not on username alone.</p>
    *
    * @param uName    the username for the new record; must not be {@code null}
    * @param password the password for the new record
    * @param se       the subsystem to associate with the new record
    * @param sr       the role to assign within the subsystem
    */
   public void addUser
   (
      String uName,
      String password,
      SubsystemEnums se,
      SubsystemRoles sr
   )
   {
      final boolean b = find(uName, password, se, sr);
      if (b) return;
      ACSRecord aR = new ACSRecord(uName, password, se, sr);
      try {
         fos = new FileOutputStream(ACSFile, true);
         dos = new DataOutputStream(fos);
         writeRecord(aR);
         aList.add(aR);
         dos.flush();
         fos.close();
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   /**
    * Returns the number of unique usernames currently registered in the system,
    * excluding SysAdmin. This method rebuilds {@code sList} on every call by
    * iterating over {@code aList} and collecting distinct usernames.
    *
    * <p><b>Side effect:</b> Calling this method repopulates {@code sList}, which
    * is required by {@link #find(String)} to function correctly. Always call
    * this method before using {@code find(String)} if accurate results are
    * needed.</p>
    *
    * <p><b>Note:</b> The first record (SysAdmin) is skipped by the iterator
    * before the loop begins and is not counted.</p>
    *
    * @return the number of unique usernames in the system, not counting SysAdmin
    */
   public int getNumUsers()
   {
      sList.clear();
      Iterator itr = aList.iterator();
      itr.next();

      while (itr.hasNext())
      {
         ACSRecord aR = (ACSRecord) itr.next();
         final String u = aR.getUserName();
         if (find(u) == false)
            sList.add(u);
      }

      final int numUsers = sList.size();
      return numUsers;


   }

}