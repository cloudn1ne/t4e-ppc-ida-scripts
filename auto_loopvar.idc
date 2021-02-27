//////////////////////////////////////////
// PPC - find loopvars and comment them
// (c) cybernet, 2016
//////////////////////////////////////////

#include <idc.idc> 
#include "include/reg_args.idc"

extern debug;

static CommentLoopvar(reg_name, lv_name, start, end)
{
  auto start_ea, len;
  auto a, a_li, a_addi, a_extsh;
  auto li_val, addi_val, extsh_dreg;
  auto str;

  start_ea = end; // end of function
  len = end-start; // up to beginning of function
  if (FindLI(reg_name, start_ea, len) != "notfound")
  {
    if (debug)
      Message("Loopvar LI found for %s\n", reg_name);
    if (FindADDI_sdreg(reg_name, start_ea, len) != "notfound")
    {
        if (debug)        
          Message("Loopvar ADDI found for %s\n", reg_name);

        // start comment actions
        a=start;
        while (a <= end)
        {
          // generate some helper addresses   
          a_li=a;
          a_addi=a;
          a_extsh=a;
          if ((GetMnem(a_li) == "li") && (GetOpnd(a_li,0) == reg_name))
          {
            li_val=GetOpnd(a_li,1);
            str=sprintf("%s = %d", lv_name, li_val);
            MakeComm(a, str);   
          }
          if ((GetMnem(a_addi) == "addi") && (GetOpnd(a_addi,0) == reg_name) && (GetOpnd(a_addi,1) == reg_name) )
          {
            addi_val=GetOpnd(a_addi,2);
            if (addi_val>0)
              str=sprintf("%s=%s+%d", lv_name, lv_name, addi_val);
            if (addi_val<0)
              str=sprintf("%s=%s-%d", lv_name, lv_name, addi_val);
            if (addi_val==1)
              str=sprintf("%s++", lv_name);
            if (addi_val==-1)
              str=sprintf("%s--", lv_name); 
            MakeComm(a, str);   
          }
          if ((GetMnem(a_extsh) == "extsh") && (GetOpnd(a_extsh,1) == reg_name) )
          {
            extsh_dreg=GetOpnd(a_extsh,0);
            str=sprintf("%s = %s", extsh_dreg, lv_name); 
            MakeComm(a, str);    
          }
          a=a+4;
        }  
    }
  }
}


static main() 
{
    auto addr,start,end,code,color;
    
    //
    // START of SETTINGS
    //
    debug = 1;   
    //
    // END of SETTINGS
    //


    start=GetFunctionAttr(ScreenEA(), FUNCATTR_START);
    if (start == -1)
    {
      Message("Cursor is not in a function\n");
      return;
    }
    end=GetFunctionAttr(start, FUNCATTR_END);
 	 
    CommentLoopvar("r30", "loopvar_B", start, end);
    CommentLoopvar("r31", "loopvar_A", start, end);
}