///////////////////////////////////////////////////////////////
// Extract Maps from IDA Pro
// (c) cybernet, 2016
///////////////////////////////////////////////////////////////
#include <idc.idc> 
#include "include/reg_args.idc"

extern rename_tables;
extern dump_tables_h;
extern dump_tables_xml;
extern debug;
extern dump_tables_h_file;
extern dump_tables_xml_file;

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
static DumpXML(dim, bits, name, current_code, size_A, size_B, lut_A, lut_B, lut_R, input_A, input_B)
{
	auto fn,fh;
	auto p;
	auto str="";
	auto i,b;
	
    fh=fopen(dump_tables_xml_file, "a");
    if (!fh)
    {
      Message("unable to open %s\n",fn);
      return;    
    }    
    if ((dim==1) && (bits==8)) { size_A=size_A*2; size_B=1; }						// 1D fixed - override sizes    
    if ((dim==1) && (bits==16)) { size_A=pow(2,8-size_A)+2; size_B=1; bits=8; }		// 1D inteprol - override sizes and bits
    if (dim==2) size_B=1;

    // dump some nice header
    fprintf(fh,"<map>\n");
    fprintf(fh,"<dimension>%d</dimension>\n", dim);
    fprintf(fh,"<bits>%d</bits>\n", bits);
    fprintf(fh,"<xsize>%d</xsize>\n", size_A);
    fprintf(fh,"<ysize>%d</ysize>\n", size_B);
    fprintf(fh,"<function>%s</function>\n", name);
    fprintf(fh,"<xref_result>%s</xref_result>\n", XRefLUTs(lut_R));    
    if (dim>1)
    {
    	fprintf(fh,"<lut_a>%x</lut_a>\n", lut_A);
    	fprintf(fh,"<lut_a_name>%s</lut_a_name>\n", GetTrueName(lut_A));		
    }
	if (dim>2)
	{
		fprintf(fh,"<lut_b>%x</lut_b>\n", lut_B);
    	fprintf(fh,"<lut_b_name>%s</lut_b_name>\n", GetTrueName(lut_B));		
	}
	fprintf(fh,"<lut_r>%x</lut_r>\n", lut_R);
    fprintf(fh,"<lut_r_name>%s</lut_r_name>\n", GetTrueName(lut_R));		
	fprintf(fh,"<input_a>%x</input_a>\n", input_A);
    fprintf(fh,"<input_a_name>%s</input_a_name>\n", GetTrueName(input_A));		
	if (dim>2)
	{
		fprintf(fh,"<input_b>%x</input_b>\n", input_B);
	    fprintf(fh,"<input_b_name>%s</input_b_name>\n", GetTrueName(input_B));		
	}			
	fprintf(fh,"</map>\n");
    fclose(fh);
}

//
// Dump table into .h file
//
static DumpH(dim, bits, name, current_code, size_A, size_B, lut_A, lut_B, lut_R, input_A, input_B)
{
	auto fn,fh;
	auto p;
	auto str="";
	auto i,b;
	
    fh=fopen(dump_tables_h_file, "a");
    if (!fh)
    {
      Message("unable to open %s\n",fn);
      return;    
    }    
    if ((dim==1) && (bits==8)) { size_A=size_A*2; size_B=1; }						// 1D fixed - override sizes    
    if ((dim==1) && (bits==16)) { size_A=pow(2,8-size_A)+2; size_B=1; bits=8; }		// 1D inteprol - override sizes and bits
    if (dim==2) size_B=1;

    // dump some nice header
    fprintf(fh,"\\\\\n");
    fprintf(fh,"\\\\ MapSize: %dx%d (%d entries)\n", size_A, size_B, size_A*size_B);   
    fprintf(fh,"\\\\ MapType: %dD\n",dim);   
    fprintf(fh,"\\\\ Function: %s\n", name);     
    fprintf(fh,"\\\\ Functions using this LUT_R: %s\n", XRefLUTs(lut_R)); 
    fprintf(fh,"\\\\ LUT Bits: %d\n",bits);   
    if (dim>1)
    	fprintf(fh,"\\\\ LUT_A: 0x%x (%s)\n", lut_A, GetTrueName(lut_A));		
	if (dim>2)
		fprintf(fh,"\\\\ LUT_B: 0x%x (%s)\n", lut_B, GetTrueName(lut_B));	
	fprintf(fh,"\\\\ LUT_R: 0x%x (%s)\n", lut_R, GetTrueName(lut_R));				
	fprintf(fh,"\\\\ Input_A: 0x%x (%s)\n", input_A, GetTrueName(input_A));	
	if (dim>2)
		fprintf(fh,"\\\\ Input_B: 0x%x (%s)\n", input_B, GetTrueName(input_B));
	fprintf(fh,"\\\\\n");   
	b=bits/8;						// stepwidth in bytes

	if (dim>1)
	{
		// dump LUT A
		fprintf(fh,"uint%d_t %s[%d] = \t{", bits, GetTrueName(lut_A), size_A);
		fprintf(fh,"0x%x",GetMapData(bits,lut_A));	
		for (i=b;i<size_A*b;i=i+b)
		{
		   fprintf(fh, ", 0x%x",GetMapData(bits,lut_A+i));
		   if (i%10==0)
		    fprintf(fh,"\n\t\t\t\t\t\t\t\t\t"); 
		}
		fprintf(fh," };\n");
	}	
	if (dim>2)
	{
		// dump LUT B
		fprintf(fh,"uint%d_t %s[%d] = \t{", bits, GetTrueName(lut_B), size_B);
		fprintf(fh,"0x%x",GetMapData(bits,lut_B));
		for (i=b;i<size_B*b;i=i+b)
		{
		   fprintf(fh, ", 0x%x",GetMapData(bits,lut_B+i));
		   if (i%10==0)
		    fprintf(fh,"\n\t\t\t\t\t\t\t\t\t"); 
		}
		fprintf(fh," };\n");
	}
	// dump LUT R
	fprintf(fh,"uint%d_t %s[%d] = \t{ ", bits, GetTrueName(lut_R), size_A*size_B);
	fprintf(fh,"0x%x",GetMapData(bits,lut_R));
	for (i=b;i<(size_A*size_B)*b;i=i+b)
	{
	   fprintf(fh, ", 0x%x",GetMapData(bits,lut_R+i));
	   if (i%10==0)
	    fprintf(fh,"\n\t\t\t\t\t\t\t\t\t"); 
	}
	fprintf(fh," };\n");
	fprintf(fh,"\n\n"); 
    fclose(fh);
}


/*
** backtrack register assignments before function call happens
** to find the pointers to the LUT's
*/
static FindArgsAndDump(current_code, name, bits, dim)
{
	auto backtrack_size;
	auto size_A,size_B;
	auto lut_R,lut_A,lut_B;
	auto input_A,input_B;
	auto newname;
	auto prefix_A;
	auto prefix_B;
	auto prefix_R;

	// create prefixes based on dimension of LUT
	prefix_A=sprintf("LUT_A_%dD_", dim);
	prefix_B=sprintf("LUT_B_%dD_", dim);
	prefix_R=sprintf("LUT_R_%dD_", dim);
	backtrack_size= 4*30;
	if (dim == 3)
	{
		if (name == "LOOKUP_3D_Fixed_Byte")
		{
			size_A=FindLI("r3", current_code, backtrack_size);				// size_A	
			size_B=FindLI("r4", current_code, backtrack_size);				// size_B
			input_A=FindLIS_ADDI_LOAD("r5", current_code, backtrack_size);	// input_A	
		 	input_B=FindLIS_ADDI_LOAD("r6", current_code, backtrack_size);	// input_B			
			lut_A=FindLIS_ADDI_ADDI("r7", current_code, backtrack_size);	// lut_A			
			lut_B=FindLIS_ADDI_ADDI("r8", current_code, backtrack_size);	// lut_B
			lut_R=FindLIS_ADDI_ADDI("r9", current_code, backtrack_size);	// lut_R
		}
		else
		{
			size_A=FindLI("r3", current_code, backtrack_size);				// size_A	
			size_B=FindLI("r4", current_code, backtrack_size);				// size_B
			input_A=FindLIS_ADDI_LOAD("r5", current_code, backtrack_size);	// input_A	
		 	input_B=FindLIS_ADDI_LOAD("r6", current_code, backtrack_size);	// input_B
			lut_R=FindLIS_ADDI_ADDI("r7", current_code, backtrack_size);	// lut_R
			lut_A=FindLIS_ADDI_ADDI("r8", current_code, backtrack_size);	// lut_A
			lut_B=FindLIS_ADDI_ADDI("r9", current_code, backtrack_size);	// lut_B
		}
	}
	if (dim == 2)
	{
		size_A=FindLI("r3", current_code, backtrack_size);				// size_A			
		input_A=FindLIS_ADDI_LOAD("r4", current_code, backtrack_size);	// input_A		 	
		lut_R=FindLIS_ADDI_ADDI("r5", current_code, backtrack_size);	// lut_R
		lut_A=FindLIS_ADDI_ADDI("r6", current_code, backtrack_size);	// lut_A		
	}
	if (dim == 1)
	{
		size_A=FindLI("r3", current_code, backtrack_size);				// size_A			
		input_A=FindLIS_ADDI_LOAD("r4", current_code, backtrack_size);	// input_A		 	
		lut_R=FindLIS_ADDI_ADDI("r5", current_code, backtrack_size);	// lut_R		
	}

	if  ((((size_A != -1) && (size_B != -1) && (lut_R != -1) &&			// check if we have all for a 3D table
	    (lut_A != -1) && (lut_B != -1)) && (dim==3))					// check if we have all for a 3D table
	    ||																// OR
	    ((size_A != -1) && (lut_R != -1) && (lut_A != -1) && (dim==2))	// check if we have all for a 2D table  
	    ||
	    ((size_A != -1) && (lut_R != -1) && (dim==1)))					// check if we have all for a 1D table 
	{
		if (debug == 1)
		{
			if (dim==2) size_B=1;
			Message(" MapSize: %dx%d\n", size_A, size_B);		
			Message(" Function: %s\n", name);   		
			Message(" MapType: %dD\n", dim);   
    		Message(" LUT Bits: %d\n",bits);   
    		if (dim>1)
    			Message(" LUT_A: 0x%x (%s)\n", lut_A, GetTrueName(lut_A));    							
			if (dim>2)
				Message(" LUT_B: 0x%x (%s)\n", lut_B, GetTrueName(lut_B));
			Message(" LUT_R: 0x%x (%s)\n", lut_R, GetTrueName(lut_R));
			Message(" Input_A: 0x%x (%s)\n", input_A, GetTrueName(input_A));
			if (dim>2)
				Message(" Input_B: 0x%x (%s)\n", input_B, GetTrueName(input_B));

		}
		// prefix tables with $prefix
		if (rename_tables == 1)
		{
			 if (strstr(GetTrueName(lut_A), prefix_A)=-1)
             {
             	   newname=sprintf("%sunk_%X", prefix_A, lut_A);
             	   MakeNameEx(lut_A, newname, SN_CHECK);                   
             }
             if ((dim>2) && strstr(GetTrueName(lut_B), prefix_B)=-1)
             {
             	   newname=sprintf("%sunk_%X", prefix_B, lut_B);
             	   MakeNameEx(lut_B, newname, SN_CHECK);                   
             }
             if (strstr(GetTrueName(lut_R), prefix_R)=-1)
             {
             	   newname=sprintf("%sunk_%X", prefix_R, lut_R);
             	   MakeNameEx(lut_R, newname, SN_CHECK);                   
             }
		}
		// dump tables to .h file
		if (dump_tables_h == 1)
		{
			DumpH(dim, bits, name, current_code,size_A,size_B,lut_A,lut_B,lut_R,input_A,input_B);
		}
		// dump tables to .xml file
		if (dump_tables_xml == 1)
		{
			DumpXML(dim, bits, name, current_code,size_A,size_B,lut_A,lut_B,lut_R,input_A,input_B);
		}
	}
	else
	{
		Message("*** Error identifiyng arguments for call at %x\n\n", current_code);
	}
}


//
// find xrefs to LUT at addr "to"
// return string of all functions using this LUT
//
static XRefLUTs(to)
{
	auto  current_code, current_data, no_dxrefs;
	auto name;
	auto str="";

	name = GetTrueName(to);
   	no_dxrefs = 0;	
   	Message("Searching for x-refs to %s\n", name);
   	current_code =  DfirstB(to);
   	while(current_code != BADADDR)
   	{
      no_dxrefs++;
      if (XrefType() = 0x11)	// 0x11 = code xref
      {
        if (debug)
       		Message("0x%x DATA xref found:\n",current_code, XrefType());  
       		if (str=="")    	
       			str=sprintf("%s (0x%x)", GetFunctionName(current_code),current_code);
       		else
      			str=sprintf("%s, %s (0x%x)",str, GetFunctionName(current_code),current_code);
      	if (debug)
      		Message("\n");
      }
      current_code = DnextB(to, current_code);
      if (current_code != BADADDR && no_dxrefs > 255)
      {
         Message("   TOO MANY (%d) DATA xrefs ...\n", no_dxrefs);
         current_code = BADADDR;
      }
   	}
   	return(str);
}


//
// find xrefs to function at addr "to"
// name = name of lookup function
// bits = LUT size (8,16)
// dim = dimension of table (2,3)
//
static XRefAndDump(to, bits, dim)
{
	auto  current_code, current_data, no_cxrefs;
	auto name;

	name = GetTrueName(to);
   	no_cxrefs = 0;	
   	Message("Searching for x-refs to %s\n", name);
   	current_code =  RfirstB0(to);
   	while(current_code != BADADDR)
   	{
      no_cxrefs++;
      if (XrefType() = 0x11)	// 0x11 = code xref
      {
        if (debug)
       		Message("0x%x CODE xref found:\n",current_code, XrefType());
      	FindArgsAndDump(current_code, name, bits, dim);
      	if (debug)
      		Message("\n");
      }
      current_code = RnextB0(to, current_code);
      if (current_code != BADADDR && no_cxrefs > 255)
      {
         Message("   TOO MANY (%d) CODE xrefs ...\n", no_cxrefs);
         current_code = BADADDR;
      }
   	}
}

static main() 
{
   	auto bits, to, current_code, current_data, no_cxrefs;

   	//
   	// START of SETTINGS
   	//
   	debug = 0;
   	rename_tables = 1;
   	dump_tables_h = 0;
   	dump_tables_h_file = "\\\\10.146.248.20\\\\cn\\\\Elise ECU\\\\Lookup_functions\\\\extract\\\\tables_cup.h";
   	dump_tables_xml = 1;
   	dump_tables_xml_file = "\\\\10.146.248.20\\\\cn\\\\Elise ECU\\\\Lookup_functions\\\\extract\\\\tables_cup.xml";
   	//
   	// END of SETTINGS
   	//

  
   	// xref lookup functions, find variables, dump LUT's   
//   	XRefAndDump(0x31CC8, 8,   1);	// LOOKUP_1D_Fixed_Byte
//   	XRefAndDump(0x23590, 8,  2);	// LOOKUP_2D_Interpolate_Byte
//   	XRefAndDump(0x236E8, 16, 2);	// LOOKUP_2D_Interpolate_HalfWord
//   	XRefAndDump(0x23934, 8,  3);	// LOOKUP_3D_Interpolate_Byte
//   	XRefAndDump(0x23FB0, 16, 3);	// LOOKUP_3D_Interpolate_HalfWord
//   	XRefAndDump(0x31D34, 8,  3);	// LOOKUP_3D_Fixed_Byte - warning: has different argument ordering than other 3D functions

     // CUP260 TABLES
     XRefAndDump(0x2FB88, 8,  1);	// LOOKUP_1D_Fixed_Byte
     XRefAndDump(0x23588, 8,  2);	// LOOKUP_2D_Interpolate_Byte
     XRefAndDump(0x236E0, 16, 2);	// LOOKUP_2D_Interpolate_Halfword
     XRefAndDump(0x2392C, 8,  3);	// LOOKUP_3D_Interpolate_Byte
     XRefAndDump(0x23FA8, 16, 3);	// LOOKUP_3D_Interpolate_Halfword
     XRefAndDump(0x2FBF4, 8,  3);	// LOOKUP_3D_Fixed_Byte

}
