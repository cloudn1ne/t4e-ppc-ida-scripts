//////////////////////////////////////////////////
// PPC - auto tag global vars referenced by (r13,r2,r1)
// (c) cybernet, 2016
//////////////////////////////////////////////////

#include <idc.idc> 
#include "include/reg_args.idc"

extern debug;

static global_var_tag(addr, r_val, r_name)
{
    auto start,end;

    start=GetFunctionAttr(addr, FUNCATTR_START);
    if (start == -1)
    {
      Message("cursor is not in a function\n");
      return;
    }
    end=GetFunctionAttr(start, FUNCATTR_END);
    while (addr < end)
    {
      auto mnem = GetMnem(addr);      
      if ((mnem == "lbz") || (mnem == "lhz") || (mnem == "lwz") ||
          (mnem == "stb") || (mnem == "sth") || (mnem == "stw"))
      {
         auto ls_reg,i,j;
         auto offset,offset_reg;
         auto data_addr,opsize,rw;
         ls_reg=GetOpnd(addr,1);  
         // extract offset and reg
         i=strstr(ls_reg,"(");
         j=strstr(ls_reg,")");
         offset=xtol(substr(ls_reg,0,i));
         offset_reg=substr(ls_reg,i+1,j);  
         if (offset_reg == r_name)
         {
             // get size of write/read
             if (substr(mnem,0,1) == "l") 
             {
                  rw=dr_R;
                  if (substr(mnem,1,2) == "b") opsize=1;
                  if (substr(mnem,1,2) == "h") opsize=2;
                  if (substr(mnem,1,2) == "w") opsize=4;
             }
             else 
             {  
                  rw=dr_W;
                  if (substr(mnem,2,3) == "b") opsize=1;
                  if (substr(mnem,2,3) == "h") opsize=2;
                  if (substr(mnem,2,3) == "w") opsize=4;
             }      
             data_addr = r_val+offset;
             MakeData(data_addr, FF_BYTE, opsize, 0);     
             // add data xref
             add_dref(addr, data_addr, rw);
             Message("%x = %s %x\n", addr, offset_reg, r_val+offset);
         }         
      }
      addr=addr+4;
    }   
}

static main() 
{
    auto addr,start,end,code,color;
    auto r1_boot,r2_boot,r13_boot;
    auto r1_main,r2_main,r13_main;
    
    //
    // START of SETTINGS
    //
    debug = 1;   
    r1_boot = 0x3FFFFC; 
    r2_boot = 0x401180; 
    r13_boot = 0x401100;        
    r1_main = 0x3FFFF0; 
    r2_main = 0x400F70; 
    r13_main = 0x400F4B;        
    //
    // END of SETTINGS
    //

    auto next_func=0x1;
    while ((next_func != -1) && (next_func < 0xFFFF))
    {
        next_func=NextFunction(next_func);
        Message("%s\n", GetFunctionName(next_func));
        global_var_tag(next_func, r13_boot, "r13");        
        global_var_tag(next_func, r2_boot, "r2");
        global_var_tag(next_func, r1_boot, "r1");
    }
    ///////////////////////////////////
    // handle MAIN global vars
    ///////////////////////////////////
    next_func=0x10000;
    while ((next_func != -1) && (next_func < 0x7FFFF))
    {
        next_func=NextFunction(next_func);
        Message("%s\n", GetFunctionName(next_func));
        global_var_tag(next_func, r13_main, "r13");        
        global_var_tag(next_func, r2_main, "r2");
        global_var_tag(next_func, r1_main, "r1");
    }    
}