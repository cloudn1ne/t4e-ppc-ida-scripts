///////////////////////////////////
// PPC ISR finder
// (c) cybernet, 2016
///////////////////////////////////

#include <idc.idc> 
static tag_isr(start, stwu)
{
    auto addr,laddr,code;

    laddr=FindBinary(start, SEARCH_DOWN, stwu);		// find STWU 
    while (laddr > -1)
    {
    	Message("checking for function header at %x\n", laddr);
	    if (strstr(Name(laddr),"sub_")!=0)  // not yet a known location ? (sub_)
 	    {
		    if (MakeCode(laddr))  // try to make code out of it
		    {
		      code=GetDisasm(laddr);
		      if (strstr(code, "stwu")>-1)   // mnemonic is a STWU ?
	              {  
		     	    MakeFunction(laddr,-1);
	        		Message("created ISR function at %x\n", laddr);
	              }
		    }
	    }
	    laddr=laddr+4;	    
     	laddr=FindBinary(laddr, SEARCH_DOWN, stwu);		// find STWU
	    
    }   

}
static main() 
{    
	// find and tag functions that start with
	// stwu      r1, ??(r1)
    tag_isr(0x1, "94 21 FF A0");
    tag_isr(0x1, "94 21 FF B0");
    tag_isr(0x1, "94 21 FF C0");
    tag_isr(0x1, "94 21 FF D0");
    tag_isr(0x1, "94 21 FF E0");   
    tag_isr(0x1, "94 21 FF F0");   
}