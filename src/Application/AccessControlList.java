package Application;

import Presentation.*;

import java.util.*;
import java.io.*;
import java.nio.file.*;

/** **************** Title: CSCI121 *******************
 *
 *
 * Company: Moravian University
 *
 * @author <your name>
 *
 * @version $ Revision log: 1.0
 *
 * @see  AccessControlList
 ************************************************************************/
//
//

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


   public static void chgSAPass(String pW)
   {
      SAPassword = pW;
   }

   public static void chgFilename(String fN)
   {
      ACSFile = fN;
   }

   //
   // The Singleton Design Pattern.
   //
   public static AccessControlList Instance()
   {
      if (cf == null) cf = new AccessControlList();
      return cf;
   }

   private class ACSRecord
   {

      final private String userName;
      final private String password;
      final private SubsystemEnums subsys;
      final private SubsystemRoles subrol;

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

      public String getUserName()
         { return userName; }
      public String getPassword()
         { return password; }
      public SubsystemEnums getSubsys()
         { return subsys;   }
      public SubsystemRoles getRole()
         { return subrol;       }

   }

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

   public boolean find
   (
       String uName
   )
   {
      for (String s : sList)
         if (s.equals(uName)) return true;
      return false;
   }

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
