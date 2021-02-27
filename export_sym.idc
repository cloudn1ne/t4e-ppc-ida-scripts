////////////////////////////////////////
// EXPORT Lauterbach Trace32 SYM file
// (c) cybernet, 2017
////////////////////////////////////////

#include <idc.idc> 


static main() 
{    
    auto ea=0x100;
 	auto fh,sym_file_path;

 	sym_file_path=AskFile(1, "sym", "Symbol File");

	fh=fopen(sym_file_path, "a");
    if (!fh)
    {
      Message("unable to open %s\n",sym_file_path);
      return;    
    }    

    // dump function addr/names (0x0 - 0x7FFFF)
    while ((ea != -1) && (ea < 0x7FFFF))
    {
        ea=NextFunction(ea);
        Message("%X %s\n", ea, GetFunctionName(ea));   
        fprintf(fh,"%X %s\n", ea, GetFunctionName(ea));
    }
    Message("===== DUMP COMPLETE =====");
    fclose(fh);
}