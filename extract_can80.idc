///////////////////////////////////////////////////////////////
// Extract CAN80 Variables from IDA Pro
// (c) cybernet, 2016
///////////////////////////////////////////////////////////////
#include <idc.idc> 
#include "include/reg_args.idc"

extern rename_vars;
extern debug;
extern unused_name;
extern dump_vars_xml_file;
extern dump_vars_xml;

//
// helper to read 'bits' size from addr
static GetMapData(bits, addr)
{
	if (bits==8)
	 return(Byte(addr));
	if (bits==16)
	 return(Word(addr));	
}

// pow() helper
static pow(base, exp)
{
    auto result=1;

    while(exp) { result = result*base; exp--; }
    return result;
}

//
// Dump table into .xml file
//
static DumpXML(var_addr, var_name, var_size, var_desc)
{
	auto fn,fh;
	auto p;
	auto str="";
	auto i,b;
	
    fh=fopen(dump_vars_xml_file, "a");
    if (!fh)
    {
      Message("unable to open %s\n",fn);
      return;    
    }    
    if (var_name == unused_name)
    {
          fprintf(fh,"<var ignore=\"1\">\n");            		  
  		  fprintf(fh,"  <size>1</size>\n");
  		  fprintf(fh,"</var>\n");            		  
    }
    else
    {
          fprintf(fh,"<var>\n");            		  
          fprintf(fh,"  <name>%s</name>\n", var_name);
  		  fprintf(fh,"  <size>%d</size>\n", var_size);
  		  if (var_desc != "")
  		     fprintf(fh,"  <description>%s</description>\n", var_desc);
  		  fprintf(fh,"</var>\n");       
    }
    fclose(fh);
}



static main() 
{
   	auto bits, to, current_code, current_data, no_cxrefs;

   	//
   	// START of SETTINGS
   	//
   	debug = 0;
   	rename_vars = 1;
   	auto table_name;
   	table_name = "CANA_0x80_Variable_tbl";
   	unused_name = "CAN_Var_tbl_UNUSED_SLOT";
   	dump_vars_xml = 1;
   	dump_vars_xml_file = "\\\\10.146.248.20\\\\cn\\\\Elise ECU\\\\Lookup_functions\\\\extract\\\\vars_elise_s.xml";
   	//
   	// END of SETTINGS
   	//

    // locate table begin
    // 
    auto addr;
    auto end;
    addr = LocByName(table_name);
    if (addr == -1)
    {
       Message("\n\nunable to find table '%s'\n\n", table_name);
       return;
    }

    // iterate over table and extact addr,name,size,comments
    auto var_addr;
    auto var_name;
    auto var_size;
    auto var_cmt;
    end=0;
    while ((addr != BADADDR) && (!end))
    {
      var_addr = Dword(addr);
      var_name = GetTrueName(var_addr);
      var_size = Byte(addr+4);
      var_cmt = CommentEx(var_addr, 1);
      if (var_name == "")
      {
        var_name=sprintf("%X", var_addr);
      }      
      if (var_addr != 0x0)
      {
      	Message("%a '%s' size: %d desc: '%s'\n", var_addr, var_name, var_size, var_cmt);
      	DumpXML(var_addr, var_name, var_size, var_cmt);      
      }
      addr=addr+6;
      if (var_addr == 0x0) { end=1; }
    }
}
