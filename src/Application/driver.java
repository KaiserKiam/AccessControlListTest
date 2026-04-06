package Application;

import Presentation.*;

public class driver
{
   static public void main()
   {

      AccessControlList.chgSAPass("xyz");
      AccessControlList cf = AccessControlList.Instance();

    //  cf.dump();

      cf.addUser  ("Bill", "MyPass", SubsystemEnums.TST, SubsystemRoles.SYSTEMADMIN);
      cf.addUser("Joe", "joePass", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);

      boolean b = cf.find("Bill", "MyPass", SubsystemEnums.TST, SubsystemRoles.SYSTEMADMIN);

      if (b) System.out.println("Record was found");
      else  System.out.println("Record was NOT found");

      int nu = cf.getNumUsers();

      cf.dump();

      cf.deleteUser("Bill");

      cf.dump();

      cf.deleteUser("Joe","joePass",SubsystemEnums.DAS,SubsystemRoles.DATAANALYST);

      cf.addUser("Joe2", "joePass", SubsystemEnums.DAS, SubsystemRoles.DATAANALYST);

      nu = cf.getNumUsers();
      cf.dump();
   }
}
