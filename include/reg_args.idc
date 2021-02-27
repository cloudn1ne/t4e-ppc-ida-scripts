///////////////////////////////////////////////////////////////
// Find arguments to function calls
// (c) cybernet, 2016
///////////////////////////////////////////////////////////////
extern debug;


/*
** find load of numeric value into register
** used for loopvars
*/
static FindLI(reg_name, start_ea, len)
{
 	auto a;
	auto val="notfound";
	auto a_li;
	
	a=start_ea-len;
	while (a <= start_ea)
	{
		// generate some helper addresses		
		a_li=a;
		if ((GetMnem(a_li) == "li") && (GetOpnd(a_li,0) == reg_name))
		{
			return(GetOpnd(a_li,1));
		}
		a=a+4;
	}
	return(val);
}

/*
** find addi of numeric value with same s/d register
** used for loopvars to increase/decrease
*/
static FindADDI_sdreg(reg_name, start_ea, len)
{
 	auto a;
	auto val="notfound";
	auto a_addi;
	
	a=start_ea-len;
	while (a <= start_ea)
	{
		// generate some helper addresses		
		a_addi=a;
		if ((GetMnem(a_addi) == "addi") && (GetOpnd(a_addi,0) == reg_name) && (GetOpnd(a_addi,1) == reg_name) )
		{
			return(GetOpnd(a_addi,2));
		}
		a=a+4;
	}
	return(val);
}

/*
** find 3 stage lis, addi, lwz/lhz/lbz loads into reg_name with start_ea-start_ea+len addr range
** (used to pass input variables to the lookup functions)
*/
static FindLIS_ADDI_LOAD(reg_name, start_ea, len)
{
	auto a;
	auto val=-1;
	auto a_lis,a_addi1,a_load;
	auto lis_dreg,lis_val;
	auto addi1_sreg,addi1_dreg,addi1_val;
	auto load_dreg,load_addr;

	a=start_ea-len;
	while (a <= start_ea)
	{
		// generate some helper addresses
		a_lis=a;
		a_addi1=a+4;
		a_load=a+8;
		if ((GetMnem(a_lis) == "lis") && (GetMnem(a_addi1) == "addi") && 								// lis, addi, load sequence
			((GetMnem(a_load) == "lbz") || (GetMnem(a_load) == "lhz") || (GetMnem(a_load) == "lwz")))		
		{
			// see if the final register of addi is what we look for
			if (GetOpnd(a_load,0) == reg_name)
			{
				// check if we have a linked register sequence (lis X,val ; addi addr,X,val load Z,addr)
				lis_dreg   = GetOpnd(a_lis,0);  
				addi1_dreg = GetOpnd(a_addi1,0);  
				addi1_sreg = GetOpnd(a_addi1,1);  				
				load_dreg = GetOpnd(a_load,0);  
				load_addr= GetOpnd(a_load,1);  
				if ((lis_dreg == addi1_sreg) && (strstr(load_addr,addi1_dreg)!=-1))
				{
					lis_val    = GetOperandValue(a_lis,1); 
					addi1_val  = GetOperandValue(a_addi1,2);					
					if (debug>=2)
 					 	Message("lis_val: %x addi1_val: %x\n", lis_val, addi1_val);
					val = ((lis_val<<16) + addi1_val); 
				}
			}			
		}
		a=a+4;
	}
	return(val);
}

/*
** find 3 stage lis, addi, addi loads into reg_name with start_ea-start_ea+len addr range
** (used to pass LUT's to the lookup functions)
*/
static FindLIS_ADDI_ADDI(reg_name, start_ea, len)
{
	auto a;
	auto val=-1;
	auto a_lis,a_addi1,a_addi2;
	auto lis_dreg,lis_val;
	auto addi1_sreg,addi1_dreg,addi1_val;
	auto addi2_sreg,addi2_dreg,addi2_val;

	a=start_ea-len;
	while (a <= start_ea)
	{
		// generate some helper addresses
		a_lis=a;
		a_addi1=a+4;
		a_addi2=a+8;
		if ((GetMnem(a_lis) == "lis") && (GetMnem(a_addi1) == "addi") && (GetMnem(a_addi2) == "addi"))		// lis, addi, addi sequence
		{
			// see if the final register of addi is what we look for
			if (GetOpnd(a_addi2,0) == reg_name)
			{
				// check if we have a linked register sequence (lis X,val ; addi Y,X,val addi Z,Y,val)
				lis_dreg   = GetOpnd(a_lis,0);  
				addi1_dreg = GetOpnd(a_addi1,0);  
				addi1_sreg = GetOpnd(a_addi1,1);  				
				addi2_dreg = GetOpnd(a_addi2,0);  
				addi2_sreg = GetOpnd(a_addi2,1);  
				if ((lis_dreg == addi1_sreg) &&  (addi2_sreg == addi1_dreg))
				{
					lis_val    = GetOperandValue(a_lis,1); 
					addi1_val  = GetOperandValue(a_addi1,2);
					addi2_val  = GetOperandValue(a_addi2,2);
					if (debug>=2)
 					 	Message("lis_val: %x addi1_val: %x addi2_val: %x \n", lis_val, addi1_val, addi2_val);
					val = ((lis_val<<16) + addi1_val) + addi2_val; 
				}
			}			
		}
		a=a+4;
	}
	return(val);
}

/*
** find immediate loads into reg_name with start_ea-start_ea+len addr range
*/
static FindLI(reg_name, start_ea, len)
{
	auto a;
	auto val=-1;

	a=start_ea-len;
	while (a <= start_ea)
	{
		if ((GetMnem(a) == "li") && (GetOpnd(a,0) == reg_name))
		{
			val = GetOpnd(a,1);			
		}
		a=a+4;
	}
	return(val);
}