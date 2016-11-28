/*
 * frubee
 *
 *
 * Copyright (C) 2015-2016 Antonio Riontino
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
*/

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>		//per sleep

#include <getopt.h>		//Command-line arguments


#include <pcap.h>
#include <arpa/inet.h>
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14


using namespace std; 


struct ParametersList_Callback
{
	int IPAddressFound;
	char* IPAddress;
	pcap_t *handle;	
};

typedef struct
{
	struct ParametersList_Callback PL_Callback;
} Parametri_Callback;


typedef struct
{
	char* Cod_Nation;
	char* Name_Nation;	
	char* Phrase_Select_Nation;	
	char* Phrase_Select_Operator;	
	char* End_Record;	
} Record;

typedef struct
{
	char* Cod_Nation;   
	char* Name_Operator;
	char* Name_Operator_With_Nation;  
	char* F_Connection_Type;
	char* End_Record;
} Record_Operators;

struct record_CheckPackets
{
	int RX1;
	int TX1;
	int RX2;	
	int TX2;
};

//********** Connessione Mobile ********INIZIO 
struct record_OperatorParameters
{
	char* Name_Operator_With_Nation;  
	char* Operator_APN;
	char* Operator_DNS1;
	char* Operator_DNS2;	
	char* End_Record;	
};
//********** Connessione Mobile ********FINE 

// IP header
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)


//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

char* f_result_of_shell (char* par_shell_command)
{ 
	char c;
	int k;		
	FILE *fp;
	string str_result;
	char* result;
	string str_c;	

	fp = popen(par_shell_command, "r");

	for ( k=1; k<=1000; k++ )  //1000 is OK?
	{	
		c=fgetc(fp); 
		str_c=c; 

		if (str_c == "\n") 
		{		
			break;
		}
		
		str_result=str_result+str_c;	
		result=strdup(str_result.c_str());	
	}	

	return result;
}


/* 
 * F_CreatesFileSelectedNation
 * Riceve
 * Scrive file:
 * /tmp/SelectedNation.txt (contiene il codice nazione selezionato)
 * /tmp/PhraseSelectOperator.txt
*/
int F_CreatesFileSelectedNation(char* par_name_nation)
{
	FILE *file, *file_selected_nation, *file_phrase_select_operator;
	Record r;
	char name_nation_to_search[40];

	int ret = 2;


	char c;
	string str_c;
	string str_field100, str_field200, str_field300,
		   str_field400, str_field350;
	int k;		
	char* previous_character;
	int num_characters; 
	int num_characters_nation;
	char name_nation_no_final_spaces[25];   
	char* name_nation_tmp;

	
	strcpy(name_nation_to_search,par_name_nation);

	char path_file[40] = "";
	strcpy(path_file, "/etc/Nations.txt");
	if ((file = fopen (path_file, "r")) == NULL)
	{
		cout <<  "Could not open file: " << path_file << endl;	
		return 1;
	}

	strcpy(path_file, "/tmp/SelectedNation.txt");
	if ((file_selected_nation = fopen (path_file, "w")) == NULL)
	{
		printf ("Could not create file /tmp/SelectedNation.txt\n");
		return 1;
	}

	strcpy(path_file, "/tmp/PhraseSelectOperator.txt");
	if ((file_phrase_select_operator = fopen (path_file, "w")) == NULL)
	{
		printf ("Could not create file /tmp/PhraseSelectOperator.txt\n");
		return 1;
	}

	while ( !feof(file) )	
	{
		str_field100  = ""; str_field200 = ""; str_field300  = ""; 
		str_field400  = "";	str_field350 = "";

		num_characters=0;
		num_characters_nation=0;
		for ( k=1; k<=237; k++ )
		{	
			c=fgetc(file);  
			str_c=c; 

			if ( k <=10 ) 
			{	
				if (isspace(c) == 0) 
				{
					str_field100=str_field100+str_c;	
					r.Cod_Nation=strdup(str_field100.c_str());	
				}			
			}

			if (( k >=11 ) & ( k <=35 ))
			{	
				num_characters=num_characters+1;
				
				if ( (isspace(c) != 0) & ( (strcmp(previous_character," ") == 0)) )
				{
					if (num_characters_nation == 0)
					{	
						num_characters_nation=num_characters-2;
						//ho dovuto usare "name_nation_no_final_spaces" perche' con "r.Name_Nation" non funzionava
						strncpy (name_nation_no_final_spaces, name_nation_tmp, num_characters_nation); 
						name_nation_no_final_spaces[num_characters_nation]='\0';	
						string str_name_nation_no_final_spaces = name_nation_no_final_spaces;  
						r.Name_Nation = strdup(str_name_nation_no_final_spaces.c_str());
					}
				}
				else
				{
					str_field200=str_field200+str_c;	
					name_nation_tmp=strdup(str_field200.c_str());	
				}
			}

			if (( k >=36 ) & ( k <=135 ))
			{	str_field300=str_field300+str_c;	r.Phrase_Select_Nation=strdup(str_field300.c_str());	}

			if (( k >=136 ) & ( k <=235 ))
			{	str_field350=str_field350+str_c;	r.Phrase_Select_Operator=strdup(str_field350.c_str());	}

			if (( k >=236 ) & ( k <=236 ))
			{	str_field400=str_field400+str_c;	r.End_Record=strdup(str_field400.c_str());	}

			previous_character = strdup(str_c.c_str());
		}		

		if (strcmp(r.Name_Nation,name_nation_to_search) == 0)  
		{
			fprintf (file_selected_nation, "%-s\n", r.Cod_Nation);			
			fprintf (file_phrase_select_operator, "%-s\n", r.Phrase_Select_Operator);				
			ret=0;
			break;
		}
	}
	fclose (file);
	fclose (file_selected_nation);
	fclose (file_phrase_select_operator);	

	if ( ret == 2 ) 
	{	
		cout <<  "The Nation \"" << name_nation_to_search << "\" is not present in the file \"/etc/Nations.txt\""<< endl;	
	}

	return ret;
}




/*
 * F_CreatesScriptSelectNation
 * Riceve: niente
 * Ritorna:
 * crea lo script /tmp/SelectNation
*/ 
int F_CreatesScriptSelectNation()
{
	FILE *file, *file_script;
	Record r;


	char c;
	string str_c;
	string str_field100, str_field200, str_field300, 
		   str_field400, str_field350;
	int k;		
	char* previous_character;
	int num_characters; 
	int num_characters_nation;
	char name_nation_no_final_spaces[25];   
	char* name_nation_tmp;

	char list[2500] = "";		
	char* str_to_export;		
	char file_nations[200];
	char path_file[40] = "";


	strcpy(file_nations,"/etc/Nations.txt");	
	if ((file = fopen (file_nations, "r")) == NULL)
	{
		cout << "Could not open file " << file_nations << endl;
		return 1;
	}

	strcpy(path_file, "/tmp/SelectNation");
	if ((file_script = fopen (path_file, "w")) == NULL)
	{
		printf ("Could not create file /tmp/SelectNation\n");
		return 1;
	}		

	while ( !feof(file) )	
	{
		str_field100  = ""; str_field200  = ""; str_field300  = ""; 
		str_field400  = "";	str_field350 = "";

		num_characters=0;
		num_characters_nation=0;
		for ( k=1; k<=237; k++ )
		{	
			c=fgetc(file);  
			str_c=c; 

			if ( k <=10 ) 
			{	
				if (isspace(c) == 0) 
				{
					str_field100=str_field100+str_c;	
					r.Cod_Nation=strdup(str_field100.c_str());	
				}			
			}

			if (( k >=11 ) & ( k <=35 ))
			{	
				num_characters=num_characters+1;
				
				if ( (isspace(c) != 0) & ( (strcmp(previous_character," ") == 0)) )
				{
					if (num_characters_nation == 0)
					{	
						num_characters_nation=num_characters-2;
						//ho dovuto usare "name_nation_no_final_spaces" perche' con "r.Name_Nation" non funzionava
						strncpy (name_nation_no_final_spaces, name_nation_tmp, num_characters_nation); 
						name_nation_no_final_spaces[num_characters_nation]='\0';	
						string str_name_nation_no_final_spaces = name_nation_no_final_spaces;  
						r.Name_Nation = strdup(str_name_nation_no_final_spaces.c_str());
					}
				}
				else
				{
					str_field200=str_field200+str_c;	
					name_nation_tmp=strdup(str_field200.c_str());	
				}
			}

			if (( k >=36 ) & ( k <=135 ))
			{	str_field300=str_field300+str_c;	r.Phrase_Select_Nation=strdup(str_field300.c_str());	}

			if (( k >=136 ) & ( k <=235 ))
			{	str_field350=str_field350+str_c;	r.Phrase_Select_Operator=strdup(str_field350.c_str());	}

			if (( k >=236 ) & ( k <=236 ))
			{	str_field400=str_field400+str_c;	r.End_Record=strdup(str_field400.c_str());	}

			previous_character = strdup(str_c.c_str());
		}		

		//Primo Parametro
		strcat(list,"\"");
		strcat(list,r.Name_Nation);
		strcat(list,"\" ");

		//Secondo Parametro
		strcat(list,"\"");
		strcat(list,r.Phrase_Select_Nation);
		strcat(list,"\"  ");

	}

	//1° Row
	str_to_export="#!/bin/sh";
	fprintf (file_script, "%-s\n", str_to_export);

	//2° Row
	str_to_export="dialog --no-cancel --menu ";
	fprintf (file_script, "%-s", str_to_export);

	fprintf (file_script, "%-s", "\"Frubee\"");	
	
	str_to_export=" 0 0 0 \\";
	fprintf (file_script, "%-s\n", str_to_export);	

	//3° Row
	fprintf (file_script, "%-s", list);	

	str_to_export="2> /tmp/file_selected_nation.txt";
	fprintf (file_script, "%-s\n", str_to_export);	

	fclose (file);
	fclose (file_script);		

	return 0;
}



/*
 * F_CreatesScriptSelectOperator
 * Riceve: Codice nazione da cercare
 * Ritorna:
 *   crea lo script /tmp/SelectOperator
 * 
 *  legge file:
 *    /tmp/Operators_tmp.txt 
 *    /tmp/PhraseSelectOperator.txt : per debug basta che lo crei inserendo es. CIAO 
*/
int F_CreatesScriptSelectOperator (char* par_cod_nation)
{

	FILE *file_operators,  *file_script;
	Record_Operators r;
	char shell_command[200];

	char c;
	string str_c;
	string str_field100, str_field200, str_field300,
		   str_field400, str_field500;
	int k;			
	char* previous_character;	
	int num_characters; 
	int num_characters_operator;
	char name_operator_no_final_spaces[40];
	char* name_operator_tmp;

	char Cod_Nation_To_Search[5];		//il codice e' di 3
	char list[2500] = "";		
	char* str_to_export;			
	char path_file[40] = "";	


	strcpy(Cod_Nation_To_Search,par_cod_nation);

	strcpy(path_file, "/tmp/Operators_tmp.txt");
	if ((file_operators = fopen (path_file, "r")) == NULL)  
	{
		printf ("1) Could not open file /tmp/Operators_tmp.txt\n");
		return 1;
	}

	strcpy(path_file, "/tmp/SelectOperator");
	if ((file_script = fopen (path_file, "w")) == NULL)
	{
		printf ("Could not create file /tmp/SelectOperator\n");
		return 1;
	}
	
	while ( !feof(file_operators) )	
	{

  		str_field100  = ""; str_field200  = ""; str_field300  = ""; 
		str_field400  = "";	str_field500  = "";	  

		num_characters=0;
		num_characters_operator=0;
		  
		for ( k=1; k<=117; k++ )
		{	
			c=fgetc(file_operators);  
			str_c=c; 
			if ( k <=10 ) 
			{	
				if (isspace(c) == 0) 
				{
					str_field100=str_field100+str_c;	
					r.Cod_Nation=strdup(str_field100.c_str());	
				}			
			}

			// Se modifichi la lunghezza, modificala anche a "name_operator_no_final_spaces" 
			if (( k >=11 ) & ( k <=50 ))
			{	
				num_characters=num_characters+1;
				
				if ( (isspace(c) != 0) & ( (strcmp(previous_character," ") == 0)) )
				{
					if (num_characters_operator == 0)
					{	
						num_characters_operator=num_characters-2;
						//ho dovuto usare "name_operator_no_final_spaces" perche' con "r.Name_Nation" non funzionava
						strncpy (name_operator_no_final_spaces, name_operator_tmp, num_characters_operator); 
						name_operator_no_final_spaces[num_characters_operator]='\0';	
						string str_name_operator_no_final_spaces = name_operator_no_final_spaces;  
						r.Name_Operator = strdup(str_name_operator_no_final_spaces.c_str());
					}
				}
				else
				{
					str_field200=str_field200+str_c;	
					name_operator_tmp=strdup(str_field200.c_str());	

				}
			}

			if (( k >=51 ) & ( k <=110 ))
			{	str_field300=str_field300+str_c;	r.Name_Operator_With_Nation=strdup(str_field300.c_str());	}

			
			if (( k >=111 ) & ( k <=115 ))
			{	str_field400=str_field400+str_c;	r.F_Connection_Type=strdup(str_field400.c_str());	}
			
			
			if (( k >=116 ) & ( k <=116 ))
			{	str_field500=str_field500+str_c;	r.End_Record=strdup(str_field500.c_str());	}

			previous_character = strdup(str_c.c_str());			
		
		} 
		
	 	if (strcmp(r.Cod_Nation,Cod_Nation_To_Search) == 0)
		{
			//Primo Parametro
			strcat(list,"\"");
			strcat(list,r.Name_Operator);
			strcat(list,"\" ");

			//Secondo Parametro
			strcat(list,"\"\"  ");
		}
	}


	//scrivi in file
	//1° Row
	str_to_export="#!/bin/sh";
	fprintf (file_script, "%-s\n", str_to_export);

	//2° Row
	//--aspect : larghezza
	str_to_export="dialog --aspect 40 --no-cancel --menu ";
	fprintf (file_script, "%-s", str_to_export);

	//Frase
	str_to_export="\"";fprintf (file_script, "%-s", str_to_export);

	strcpy(shell_command,"cat /tmp/PhraseSelectOperator.txt");
	char* phrase=f_result_of_shell(shell_command);
	fprintf (file_script, "%-s", phrase);
	str_to_export="\"";fprintf (file_script, "%-s", str_to_export);

	str_to_export=" 0 0 0 \\";
	fprintf (file_script, "%-s\n", str_to_export);	
	
	
	//3° Row
	fprintf (file_script, "%-s", list);	
	
	str_to_export=" 2> /tmp/file_selected_operator.txt";
	fprintf (file_script, "%-s\n", str_to_export);	
	
	fclose (file_operators);
	fclose (file_script);	

	return 0;

}


/* 
 * F_CreatesFileSelectedOperator
 * Riceve: Nome Operatore 
 * Ritorna: 
 *    crea file 
 *       /tmp/SelectedOperator.txt (contiene nazione.operatore) e 
 *       /tmp/TypeSelectedOperator.txt
*/
int F_CreatesFileSelectedOperator (char* par_name_operator)
{

	FILE *file;
	Record_Operators r;

	int ret = 2;

	char c;
	string str_c;
	string str_field100, str_field200, str_field300,
		   str_field400, str_field500;
	int k;			
	char* previous_character;	
	int num_characters; 
	int num_characters_operator;

	char shell_command[200];		
	char path_file[40] = "";
	char name_operator_no_final_spaces[40];
	char* name_operator_tmp;
	char name_operator_to_search[40];	
	char* result_of_shell;
	char* Cod_Nation_To_Search;


	strcpy(shell_command,"cat /tmp/SelectedNation.txt");
	result_of_shell=f_result_of_shell(shell_command);
	Cod_Nation_To_Search = result_of_shell;   

	strcpy(name_operator_to_search,par_name_operator);

	strcpy(path_file, "/tmp/Operators_tmp.txt");
	if ((file = fopen (path_file, "r")) == NULL)  
	{
		printf ("2) Could not open file /tmp/Operators_tmp.txt\n");
		return 1; 
	}


	while ( !feof(file) )	
	{
  		str_field100  = ""; str_field200  = ""; str_field300  = ""; 
		str_field400  = "";	str_field500  = "";	  

		num_characters=0;
		num_characters_operator=0;
		  
		for ( k=1; k<=117; k++ )  
		{	
			c=fgetc(file);  
			str_c=c; 

			if ( k <=10 ) 
			{	
				if (isspace(c) == 0) 
				{
					str_field100=str_field100+str_c;	
					r.Cod_Nation=strdup(str_field100.c_str());	
				}			
			}

			//Se modifichi la lunghezza, modificala anche a 
			//"name_operator_no_final_spaces" e "name_operator_to_search"
			if (( k >=11 ) & ( k <=50 ))
			{	
				num_characters=num_characters+1;
				
				if ( (isspace(c) != 0) & ( (strcmp(previous_character," ") == 0)) )
				{
					if (num_characters_operator == 0)
					{	
						num_characters_operator=num_characters-2;
						//ho dovuto usare "name_operator_no_final_spaces" perche' con "r.Name_Nation" non funzionava
						strncpy (name_operator_no_final_spaces, name_operator_tmp, num_characters_operator); 
						name_operator_no_final_spaces[num_characters_operator]='\0';	
						string str_name_operator_no_final_spaces = name_operator_no_final_spaces;  
						r.Name_Operator = strdup(str_name_operator_no_final_spaces.c_str());
					}
				}
				else
				{
					str_field200=str_field200+str_c;	
					name_operator_tmp=strdup(str_field200.c_str());	

				}
			}

			if (( k >=51 ) & ( k <=110 ))
			{	str_field300=str_field300+str_c;	r.Name_Operator_With_Nation=strdup(str_field300.c_str());	}

			if (( k >=111 ) & ( k <=115 ))
			{	str_field400=str_field400+str_c;	r.F_Connection_Type=strdup(str_field400.c_str());	}
			
			if (( k >=116 ) & ( k <=116 ))
			{	str_field500=str_field500+str_c;	r.End_Record=strdup(str_field500.c_str());	}

			previous_character = strdup(str_c.c_str());			
		} 

		if  ( (strcmp(r.Name_Operator,name_operator_to_search) == 0)  && 
			 (strcmp(r.Cod_Nation,Cod_Nation_To_Search) == 0)
			 )
			 {

			strcpy(shell_command,"echo ");
			strcat(shell_command,r.Name_Operator_With_Nation);
			strcat(shell_command," > /tmp/SelectedOperator.txt");	
			system(shell_command);

			strcpy(shell_command,"echo ");
			strcat(shell_command,r.F_Connection_Type);
			strcat(shell_command," > /tmp/TypeSelectedOperator.txt");	
			system(shell_command);

			ret=0;				 
			break;
		}
	}
	fclose (file);

	if ( ret == 2 ) 
	{	
		//invece del codice nazione, dovresti mettere il nome
		cout <<  "The operator \"" << name_operator_to_search << "\" is not present for the Nation \"" << Cod_Nation_To_Search << "\"" << endl;	
	}

	return ret;
}


int F_CreatesFileRouterTmp(char* cod_nation_to_search, int file_type)
{

	//cod_nation_to_search: andrebbe bene anche int, ma visto che l'ho ricevuto char* ...

	char shell_command[200];	
	char* result_of_shell;
	char file_for_menu[70];
	char file_for_router_IP_addresses[70];
	char file_containing_IP_addresses[70];
	char file_containing_name[70];
	int lenght_row;
	int ret;
	int i;
	int x;
	int k;
	int n_rows;
	char* cod_nation_router_operator;		//andrebbe  bene anche int, ma per comodita' di cast l'ho messa cosi'
	char i_char[4];	
	char* nation_with_router_operator;
	int lenght_nation_with_router_operator;
	char* router_operator;
	int lenght_router_operator;
	int n_spaces;
	char* Row;
	int NStrRow;
	char pos_to_control[3];
	char* StrToInsert;
	FILE *file_router, *file_router_IP_addresses;


	if ( file_type == 1 )
	{
		strcpy(file_for_menu,"/tmp/router_operators_tmp.txt");
		strcpy(file_for_router_IP_addresses,"/tmp/router_IP_addresses_operators_tmp.txt");
		strcpy(file_containing_IP_addresses,"/etc/RouterOperatorsIPAddresses.txt");
		strcpy(file_containing_name,"/etc/RouterOperatorsIPAddressesName.txt");
	}
	else if ( file_type == 2 )
	{
		strcpy(file_for_menu,"/tmp/router_tmp.txt");
		strcpy(file_for_router_IP_addresses,"/tmp/router_IP_addresses_tmp.txt");
		strcpy(file_containing_IP_addresses,"/etc/RouterIPAddresses.txt");
		strcpy(file_containing_name,"/etc/RouterIPAddressesName.txt");
	}

	//Impostare lunghezza del tracciato del file "/etc/Operators_Mobile.txt"
	lenght_row=116;		

	if ((file_router = fopen (file_for_menu, "w")) == NULL)
	{
		cout << "connect - Could not open file:"  << file_for_menu << endl;
		return 1;
	}		

	if ((file_router_IP_addresses = fopen (file_for_router_IP_addresses, "w")) == NULL)
	{
		cout << "connect - Could not open file: "  << file_for_router_IP_addresses << endl;
		return 1;
	}		

	strcpy(shell_command,"cat ");			
	strcat(shell_command,file_containing_IP_addresses);			
	strcat(shell_command," | wc -l");			
	result_of_shell=f_result_of_shell(shell_command);
	n_rows=atoi(result_of_shell);

	i=1;
	while ( i <= n_rows ) 
	{
		sprintf(i_char,"%d",i);

		strcpy(shell_command,"head -n");			
		strcat(shell_command,i_char);			
		strcat(shell_command," ");			
		strcat(shell_command,file_containing_IP_addresses);			
		strcat(shell_command," | tail -n1 | awk ' { print $1 } '");			

		result_of_shell=f_result_of_shell(shell_command);
		cod_nation_router_operator=result_of_shell;

		strcpy(shell_command,"head -n");			
		strcat(shell_command,i_char);			
		strcat(shell_command," ");			
		strcat(shell_command,file_containing_IP_addresses);			
		strcat(shell_command," | tail -n1 | awk ' { print $2 } '");			
		result_of_shell=f_result_of_shell(shell_command);
		nation_with_router_operator=result_of_shell;
		lenght_nation_with_router_operator=strlen (nation_with_router_operator);

		//carica il campo del modem dell'operatore: e' fra  #10I# e #10F#  
		//router_operator=`cat $file_containing_name |  grep $nation_with_router_operator | sed -e 's/.*#10I#//' | sed -e 's/\#10F#[^\/]*$//'`
		strcpy(shell_command,"cat ");			
		strcat(shell_command,file_containing_name);			
		strcat(shell_command," |  grep ");			
		strcat(shell_command,nation_with_router_operator);			
		strcat(shell_command," | sed -e 's/.*#10I#//' | sed -e 's/\\#10F#[^\\/]*$//'");			
		result_of_shell=f_result_of_shell(shell_command);
		router_operator=result_of_shell;
		lenght_router_operator=strlen (router_operator);

		//calcola spazi da aggiungere
		//-10: lunghezza primo campo
		//-6:  lunghezza ultimi 2 campi (f_connection_type e X)
		n_spaces=lenght_row - lenght_router_operator - lenght_nation_with_router_operator -10 -6;

		if ( file_type == 1 )
		{
			fprintf (file_router,cod_nation_router_operator);		
		}	
		else if ( file_type == 2 )
		{
			fprintf (file_router,cod_nation_to_search);		
		}

		fprintf (file_router,"       ");		
		fprintf (file_router,router_operator);		

		//non devo calcolare gli spazi da aggiungere per incolonnare. La lunghezza
		//del campo "router_operator" e' giusta in file /etc/RouterOperatorsIPAddressesName.txt
		fprintf (file_router,nation_with_router_operator);		

		x=1;
		char space[50]="";
		while ( x <= n_spaces )
		{ 	
			strcat(space," ");		
			x++;		
		}
		fprintf (file_router,space);		

		fprintf (file_router,"2");		//Tipo Operatore
		fprintf (file_router,"    ");		
		fprintf (file_router,"X");		
		fprintf (file_router,"\n");		

		strcpy(shell_command,"head -n");			
		strcat(shell_command,i_char);			
		strcat(shell_command," ");			
		strcat(shell_command,file_containing_IP_addresses);			
		strcat(shell_command," | tail -n1");			
		result_of_shell=f_result_of_shell(shell_command);
		Row=result_of_shell;

		//conta quante sono le stringhe nella riga
		strcpy(shell_command,"echo \"");			
		strcat(shell_command,Row);			
		strcat(shell_command,"\" | wc -w");			
		result_of_shell=f_result_of_shell(shell_command);
		NStrRow=atoi(result_of_shell);

		//legge tutti le stringhe, tranne la prima colonna che è il codice nazione
		k=2;
		while ( k <= NStrRow ) 		//il ciclo for non funziona durante il boot
		{
			sprintf(pos_to_control,"%d",k);

			strcpy(shell_command,"echo \"");			
			strcat(shell_command,Row);			
			strcat(shell_command,"\" | awk ' { print $");			
			strcat(shell_command,pos_to_control);			
			strcat(shell_command," } '");			
			result_of_shell=f_result_of_shell(shell_command);
			StrToInsert=result_of_shell;

			fprintf (file_router_IP_addresses,StrToInsert);		
			fprintf (file_router_IP_addresses,"       ");		

			k++;	
		}

		fprintf (file_router_IP_addresses,"\n");		

		i++;	
	}
	
	fclose (file_router_IP_addresses);			
	fclose (file_router);				

	return 0;

}


void F_DetectsSituationIPAddresses(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	Parametri_Callback *p_Callback = (Parametri_Callback *) args;

	const struct sniff_ip *ip;
	int size_ip;
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	if (size_ip == 20) 
	{

		//se entra qui e' stato trovato un indirizzo IP
		//cout << "Indirizzo IP trovato:"  << inet_ntoa(ip->ip_dst) << endl;  //debug

		//Durante il test dell'indirizzo IP privato a volte (molto poche) puo' capitare 
		//(non ho approfondito quando) che:
		//faccio il ping su "192.168.1.2" e "ip->ip_dst" e' valorizzato con "239.255.255.250" 
		//e quindi entra qui.
		//"192.168.1.2" sarebbe dovuto essere vuoto e quindi non doveva entarre qui
		//il protocollo dell'indirizzo IP "239.255.255.250" e' UDP, quindi e' necessario
		//il seguente controllo:
		//if (ip->ip_p == IPPROTO_ICMP) 	//IPPROTO_ICMP e' definito in "netinet/in.h" 
		//Aggiornamento! non posso usarlo perche' 
		//faccio il ping su "192.168.1.3" e "ip->ip_dst" puo' essere valorizzato anche 
		//con "192.168.1.2" 

		//Controllo necessario perche' qualche volta in "ip->ip_dst" c'e' un valore 
		//diverso da "p_Callback[0].PL_Callback.IPAddress"
		//Non ho approfondito
		if  (strcmp(p_Callback[0].PL_Callback.IPAddress,inet_ntoa(ip->ip_dst)) == 0) 		// Se sono uguali...
		{
			//se entra qui ha trovato il router o gli indirizzi IP gia' occupati

			//Visto che per ora il programma non gestisce questi casi, ma si limita a rilevarli,
			//non ho aggiunto la gestione (es. rilevazione indirizzo IP non corretta, protocollo 
			//rilevato)

			p_Callback[0].PL_Callback.IPAddressFound=1;
			pcap_breakloop(p_Callback[0].PL_Callback.handle);
		}
	}

	return;
}


int F_TestIPAddress(char* dev, int num_packets, struct ParametersList_Callback *PL_Callback)
{
	char shell_command[200];
	char errbuf[PCAP_ERRBUF_SIZE];		//Error string
	pcap_t *handle;
	//int ret;

	//Open the device for sniffing
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL)
	{
		strcpy(shell_command,"echo \"Couldn't open device ");		
		strcat(shell_command,errbuf);	
		strcat(shell_command,"\"");	
		strcat(shell_command," > /tmp/NOCONNECT.err");	
		system(shell_command);
		return 1;
	}

	struct ParametersList_Callback EP_Callback_ToPass;
	EP_Callback_ToPass.IPAddressFound = PL_Callback->IPAddressFound;
	EP_Callback_ToPass.IPAddress        = PL_Callback->IPAddress;
	EP_Callback_ToPass.handle             = handle;
	Parametri_Callback p_Callback[1] = {EP_Callback_ToPass};


	//pcap_loop torna -2 se interrotto da pcap_breakloop
/*	ret=*/ pcap_loop(handle, num_packets, F_DetectsSituationIPAddresses, (u_char*)&p_Callback);	

	PL_Callback->IPAddressFound=p_Callback[0].PL_Callback.IPAddressFound;
	PL_Callback->IPAddress=p_Callback[0].PL_Callback.IPAddress;

	pcap_close(handle);

	return 0;
}



/*
 * F_FindIPAddressRouter
 * Riceve: Marca Router
 * Calcola:
 *   IPAddressRouter : Indirizzo IP del Router 
*/ 
int F_FindIPAddressRouter(char* par_name_operator_with_nation, char* &IPAddressRouter)
{

	char shell_command[200];	
	int ret;	

	char* result_of_shell;
	char* IPAddressesList; 
	int NIPAddressesToCheck;
	int i;
	char* IPAddressRouterToCheck;
	int n;
	char pos_to_control[2];

  	char* RouterBrand; 			//vedi se cambiare nome alla variabile
	RouterBrand = par_name_operator_with_nation;		

	char* dev;
	dev = "eth0";
	int num_packets;
	struct ParametersList_Callback PL_Callback;

	strcpy(shell_command,"cat /tmp/RouterIPAddresses_tmp.txt | grep ");		
	strcat(shell_command,RouterBrand);
	result_of_shell=f_result_of_shell(shell_command);
	IPAddressesList=result_of_shell;

	//conta quante sono le stringhe nella riga
	strcpy(shell_command,"echo \"");		
	strcat(shell_command,IPAddressesList);
	strcat(shell_command,"\" | wc -w");
	result_of_shell=f_result_of_shell(shell_command);
	NIPAddressesToCheck=atoi(result_of_shell);

	//legge tutti gli indirizzi IP, tranne la prima colonna che è la marca del router
	i=2;
	while ( i <= NIPAddressesToCheck )
	{
		sprintf(pos_to_control,"%d",i);

		//Controllo tutta la stringa contenente gli indirizzi IP
		strcpy(shell_command,"echo \"");		
		strcat(shell_command,IPAddressesList);
		strcat(shell_command,"\" | awk ' { print $");
		strcat(shell_command,pos_to_control);			
		strcat(shell_command," } '");
		result_of_shell=f_result_of_shell(shell_command);
		IPAddressRouterToCheck=result_of_shell;

		//aggiunto "2>&1 ", altrimenti in shell appare:
		//ping: Warning: source address might be selected on device other than eth0.
		strcpy(shell_command,"ping -I eth0 ");
		strcat(shell_command,IPAddressRouterToCheck);
		strcat(shell_command," >> /dev/null 2>&1 &");
		system(shell_command);

		PL_Callback.IPAddressFound=0;
		PL_Callback.IPAddress=IPAddressRouterToCheck;

		//Al primo lancio, se indirizzo corretto ,il router viene rilevato al terzo/quarto pacchetto
		//Nei lanci successivi la maggior parte delle volte viene rilevato al primo.
		//E' successo che il router viene rilevato al settimo (non era il primo lancio)
		//Avrei potuto anche mettere un numero inferiore...ma per sicurezza ho messo 15
		num_packets = 15;

		ret=F_TestIPAddress(dev, num_packets, &PL_Callback);
		if  ( ret != 0 ) 			
		{
			return 1;
		}

		strcpy(shell_command,"killall -s KILL ping");		
		system(shell_command);

		if ( PL_Callback.IPAddressFound == 1 )
		{
			break;
		}

		i++;
	}

	if ( PL_Callback.IPAddressFound == 1 )
	{
		IPAddressRouter=PL_Callback.IPAddress;
	} 
	else
	{
		strcpy(shell_command,"echo \"2) CONNECTION ERROR: No routers found\"");		
		strcat(shell_command," > /tmp/NOCONNECT.err");	
		system(shell_command);
		return 1;
	} 

	return 0;
}


/*  
 * F_FindIPAddressFree
 * 
 * 	Rilevazione IP gia' occupati
 *  Riceve: 
 * Calcola:
 *     IPLibero : IP da assegnare al client
*/
int F_FindIPAddressFree(char* IPAddressRouter, int &fourth_triplet_start, int fourth_triplet_end)
{

	char shell_command[200];	
	int ret;	

	char* result_of_shell;

	int n;
	int triplet;

	char triplet_position[2];
	char triplet_char[4];
	char First3Triplets[20];
	char* IPAddressFree = "";

	char i_char[4];

	char IPAddressToCheck[20];	

	char* dev;
	dev = "eth0";
	int num_packets;
	struct ParametersList_Callback PL_Callback;


	n=1;
	strcpy(First3Triplets,"");	
	while ( n <= 3 )
	{
		sprintf(triplet_position,"%d",n);
		
		strcpy(shell_command,"echo \"");		
		strcat(shell_command,IPAddressRouter);
		strcat(shell_command,"\" | cut -d'.' -f");
		strcat(shell_command,triplet_position);			
		result_of_shell=f_result_of_shell(shell_command);
		triplet=atoi(result_of_shell);					//da char a int l'ho fatto perche' copiato da sopra, ma non servirebbe

		sprintf(triplet_char,"%d",triplet);				//cast da int a char (questo cast e' una conseguenza del cast sopra)  
		strcat(First3Triplets,triplet_char);		
		strcat(First3Triplets,".");

		n++;   
	}


	//Elenco IP liberi (scommenta) - debug
	//strcpy(shell_command,"rm -f /tmp/elenco_IP_liberi.txt");
	//system(shell_command);


	while ( fourth_triplet_start <= fourth_triplet_end )
	{												
		sprintf(i_char,"%d",fourth_triplet_start);
		strcpy(IPAddressToCheck,First3Triplets);		
		strcat(IPAddressToCheck,i_char);				

		//aggiunto "2>&1 ", altrimenti in shell appare:
		//ping: Warning: source address might be selected on device other than eth0.
		strcpy(shell_command,"ping -I eth0 ");
		strcat(shell_command,IPAddressToCheck);				
		strcat(shell_command," >> /dev/null 2>&1 &");
		system(shell_command);							

		PL_Callback.IPAddressFound=0;
		PL_Callback.IPAddress=IPAddressToCheck;

		//La maggior parte delle volte il client attivo viene rilevato alla prima volta.
		//Qualche volta viene rilevato alla settima volta, pochissime alla decima volta.
		//Per sicurezza ho messo 15. 
		//Tanto appena rileva che l'indirizzo IP e' attivo, la ricerca si ferma e 
		//passa al successivo. 
		//L'unica volta che fa sicuramente 15 giri e' quando trova il primo indirizzo IP libero.
		//Per provare tutto il giro, cerca stringhe "Elenco IP liberi" (ci mette tanto)
		num_packets = 15;
		ret=F_TestIPAddress(dev, num_packets, &PL_Callback);
		if  ( ret != 0 ) 			
		{
			return 1;
		}

		strcpy(shell_command,"killall -s KILL ping");		
		system(shell_command);

		if ( PL_Callback.IPAddressFound == 0 )
		{

			//Elenco IP liberi (scommenta) - debug
			//strcpy(shell_command,"echo \"");		
			//strcat(shell_command,PL_Callback.IPAddress);		
			//strcat(shell_command,"\" >> /tmp/elenco_IP_liberi.txt");		
			//system(shell_command);

			IPAddressFree=PL_Callback.IPAddress;
			break;			//Elenco IP liberi (commenta) - debug
		}
		fourth_triplet_start++;   				   						
	}												

	if  (strcmp(IPAddressFree,"") == 0)
	{
		strcpy(shell_command,"echo \"Were not found free IP Addresses.\"");		
		strcat(shell_command," > /tmp/NOCONNECT.err");	
		system(shell_command);
		return 1;
	}	

	strcpy(shell_command,"echo ");		
	strcat(shell_command,IPAddressFree);
	strcat(shell_command," > /tmp/IPAddressFree.txt");		
	system(shell_command);

	return 0;
}



void F_FindPackets(char* IPAddressRouter, struct record_CheckPackets *r_CheckPackets)
{

	char shell_command[200];	
	char* result_of_shell;

	//valore iniziale
	//sed: prende da : in poi
	strcpy(shell_command,"ifconfig eth0 | grep \"RX packets\" | awk ' { print $2 } ' |  sed -e 's/.*://'");		
	result_of_shell=f_result_of_shell(shell_command);
	r_CheckPackets->RX1=atoi(result_of_shell);

	strcpy(shell_command,"ifconfig eth0 | grep \"TX packets\" | awk ' { print $2 } ' |  sed -e 's/.*://'");		
	result_of_shell=f_result_of_shell(shell_command);
	r_CheckPackets->TX1=atoi(result_of_shell);

	//
	strcpy(shell_command,"ping -c2 ");
	strcat(shell_command,IPAddressRouter);
	strcat(shell_command," >> /dev/null &");
	system(shell_command);

	sleep(2);	//meno di 1 secondo non funziona correttamente il ciclo
						
	//
	strcpy(shell_command,"ifconfig eth0 | grep \"RX packets\" | awk ' { print $2 } ' |  sed -e 's/.*://'");		
	result_of_shell=f_result_of_shell(shell_command);
	r_CheckPackets->RX2=atoi(result_of_shell);

	strcpy(shell_command,"ifconfig eth0 | grep \"TX packets\" | awk ' { print $2 } ' |  sed -e 's/.*://'");		
	result_of_shell=f_result_of_shell(shell_command);
	r_CheckPackets->TX2=atoi(result_of_shell);

}

char* F_CheckConnection(struct record_CheckPackets *r_CheckPackets)
{
	int differenceRX;
	int differenceTX;
	char* connection;


	differenceRX=r_CheckPackets->RX2-r_CheckPackets->RX1;
	differenceTX=r_CheckPackets->TX2-r_CheckPackets->TX1;

	if ( differenceRX == 0 )
	{
		connection="NO";
	}
	else
	{
		if ( differenceTX > 1 )
		{
			connection="YES";
		}

		else
		{
			connection="NO";
		}
	}	
	
	return connection;
	
}


int F_RouterConnection(char* IPAddressRouter, char* IPAddressClient)
{
	char shell_command[500];	
	char* result_of_shell;
	char* connection;


	strcpy(shell_command,"ifconfig eth0 ");		
	strcat(shell_command,IPAddressClient);
	strcat(shell_command," netmask 255.255.255.0 up");		
	system(shell_command);

	strcpy(shell_command,"route add default gw ");		
	strcat(shell_command,IPAddressRouter);
	system(shell_command);

	struct record_CheckPackets r_CheckPackets;
	F_FindPackets(IPAddressRouter, &r_CheckPackets);
	connection=F_CheckConnection (&r_CheckPackets);
	if  (strcmp(connection,"NO") == 0)
	{
		return 1;
	}

	return 0;
	
}


//********** Connessione Mobile ********INIZIO 

void F_WriteMessage(char par_message[2000], 
					   char par_destination[100])
{
	char shell_command[2200];
	
	strcpy(shell_command,"echo ");
	strcat(shell_command,"\"");
	strcat(shell_command,par_message);
	strcat(shell_command,"\"");

	if (strcmp(par_destination,"") != 0) 
	{
		strcat(shell_command," > ");
		strcat(shell_command,par_destination);
	}
	system(shell_command);
}


void FrubeeInfo(char par_destination[100])	
{
	char msg[2000];

	strcpy(msg,"Frubee - Version 2.3.1");  F_WriteMessage(msg,par_destination);	//VersProgr
	strcpy(msg,"Designed and developed By Antonio Riontino");           F_WriteMessage(msg,par_destination);	//DevBy
	strcpy(msg,"https://github.com/tone77/frubee");                         F_WriteMessage(msg,par_destination);	//Site
}

int F_OperatorParameters(char* par_Operator, struct record_OperatorParameters *r_OperatorParameters)   
{
	//Invece di creare il file "/etc/Operators_Mobile_Parameters.txt" contenente i parametri,
	//questi li avresti potuti mettere nel file "/etc/Operators_Mobile.txt".
	//Ho creato un nuovo file perche' e' stato il modo piu' semplice e veloce per gestire i parametri
	//in un file: all'inizio dello sviluppo i parametri erano nel sorgente.

	FILE *file;
	char path_file[40] = "";

	char c;
	string str_c;
	string str_field100, str_field200, str_field300,
		   str_field400, str_field500;
	int k;	

	char* previous_character;	


	strcpy(path_file, "/etc/Operators_Mobile_Parameters.txt");
	if ((file = fopen (path_file, "r")) == NULL)
	{
		cout <<  "Could not open file: " << path_file << endl;	
		return 1;
	}

	while ( !feof(file) )	
	{
		str_field100 = ""; str_field200 = ""; str_field300  = ""; 
		str_field400 = ""; str_field500  = "";
		for ( k=1; k<=122; k++ )
		{	
			c=fgetc(file);  
			str_c=c; 

			if ( k <=60 )
			{	
				if (isspace(c) == 0) 
				{
					str_field100=str_field100+str_c;	
					r_OperatorParameters->Name_Operator_With_Nation=strdup(str_field100.c_str());	
				}			
			}

			if (( k >=61 ) & ( k <=80 ))
			{	
				if (isspace(c) == 0) 
				{
					str_field200=str_field200+str_c;	
					r_OperatorParameters->Operator_APN=strdup(str_field200.c_str());	
				}			
			}

			if (( k >=81 ) & ( k <=100 ))
			{	
				if (isspace(c) == 0) 
				{
					str_field300=str_field300+str_c;	
					r_OperatorParameters->Operator_DNS1=strdup(str_field300.c_str());	
				}		
			}

			if (( k >=101 ) & ( k <=120 ))
			{	
				if (isspace(c) == 0) 
				{
					str_field400=str_field400+str_c;	
					r_OperatorParameters->Operator_DNS2=strdup(str_field400.c_str());	
				}		
			}

			if (( k >=121 ) & ( k <=121 ))
			{	str_field500=str_field500+str_c;	r_OperatorParameters->End_Record=strdup(str_field500.c_str());	}

			previous_character = strdup(str_c.c_str());
		}		

		if (strcmp(r_OperatorParameters->Name_Operator_With_Nation,par_Operator) == 0)  
		{
			break;
		}

	}
	fclose (file);

	return 0;
} 

 
void TheFaces(int par_Humor, char par_destination[100])
{
	int Humor=par_Humor;
	char msg[2000];

	if ( Humor == 1 ) 
	{
		strcpy(msg,"  /\\   /\\ ");                                     F_WriteMessage(msg,par_destination);	
		strcpy(msg," /    /");                                          F_WriteMessage(msg,par_destination);	
		strcpy(msg,"[@]-[@]       * * * * * * * * * * * * * * * * *");  F_WriteMessage(msg,par_destination);	
		strcpy(msg,"   ^     * * *  Connection made                *"); F_WriteMessage(msg,par_destination);	
		strcpy(msg,"  <_> * *     * * * * * * * * * * * * * * * * *");  F_WriteMessage(msg,par_destination);	
	}
	else if ( Humor == 2 ) 
	{
		strcpy(msg,"  /\\   /\\ ");                                     F_WriteMessage(msg,par_destination);	
		strcpy(msg," /    /");                                          F_WriteMessage(msg,par_destination);	
		strcpy(msg,"[.]-[.]       * * * * * * * * * * * * * * * * *");  F_WriteMessage(msg,par_destination);	
		strcpy(msg," | ^     * * *  Connection failed              *"); F_WriteMessage(msg,par_destination);	
		strcpy(msg,"  ___ * *     * * * * * * * * * * * * * * * * *");  F_WriteMessage(msg,par_destination);	
	}
}

void F_Drawings(int par_Drawing, char par_destination[100])
{
	char msg[2000];

	if ( par_Drawing == 1 ) 
	{	
		strcpy(msg," ________________________");                    F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|                        |");                   F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|         MODEM          |");                   F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|       DETECTION        |");                   F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|                        |");                   F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|                        |");                   F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|                        |");                   F_WriteMessage(msg,par_destination);	
		strcpy(msg,"|________________________|       __");          F_WriteMessage(msg,par_destination);	
		strcpy(msg," \\ ................  789  \\_____|modem__|");  F_WriteMessage(msg,par_destination);
		strcpy(msg,"  \\ ................  456  \\ ");              F_WriteMessage(msg,par_destination);
		strcpy(msg,"   \\ ................  123  \\ ");             F_WriteMessage(msg,par_destination);
		strcpy(msg,"    \\    _____________  0    \\ ");            F_WriteMessage(msg,par_destination);
		strcpy(msg,"     \\________________________\\ ");           F_WriteMessage(msg,par_destination);
		strcpy(msg,"");                                             F_WriteMessage(msg,par_destination);	
		strcpy(msg,"");                                             F_WriteMessage(msg,par_destination);	
		strcpy(msg,"");                                             F_WriteMessage(msg,par_destination);
	}
	else if ( par_Drawing == 2 ) 
	{
		strcpy(msg,"    * * *");                                        F_WriteMessage(msg,par_destination);	
		strcpy(msg," * *     * * * * * * * * *");                       F_WriteMessage(msg,par_destination);	
		strcpy(msg,"*                         *");                      F_WriteMessage(msg,par_destination);	
		strcpy(msg,"* Connection in progress  *");                      F_WriteMessage(msg,par_destination);	
		strcpy(msg,"*                         *");                      F_WriteMessage(msg,par_destination);	
		strcpy(msg," * * * * *   * * * * * * *");                       F_WriteMessage(msg,par_destination);	
		strcpy(msg,"       *  * *");                                    F_WriteMessage(msg,par_destination);	
		strcpy(msg,"      *");                                          F_WriteMessage(msg,par_destination);	
		strcpy(msg,"      *                                 O   O");    F_WriteMessage(msg,par_destination);	
		strcpy(msg,"   ___^");                                          F_WriteMessage(msg,par_destination);	
		strcpy(msg,"  /    \\  - - - - - - - - - - - - ->  O  WWW  O"); F_WriteMessage(msg,par_destination);	
		strcpy(msg,"  |[]  |");                                         F_WriteMessage(msg,par_destination);	
		strcpy(msg,"  |    |                                O   O");    F_WriteMessage(msg,par_destination);	
		strcpy(msg,"*****************************");                    F_WriteMessage(msg,par_destination);	
		strcpy(msg,"");                                                 F_WriteMessage(msg,par_destination);	
	}	
}



/*
 * F_DetectModem 
 * 		Rileva modem USB mobile
 * Trova:
 *    modem_USB_to_check
*/ 
int F_DetectModem(char* &modem_USB_to_check,
                  char process_frubee[10],
				  int par_Drawing, 
				  char* par_file_frubee_call,
			      char* par_file_flow,
				  char par_destination_drawing[100],
			      char par_destination_information[100],
			      char par_destination_message[100],
			      char par_destination_command[100],
			      char par_destination_command_with_direction[100])   
{

	int file_device_ttyUSB;
	int file_device_ttyACM;	
	char* result_of_shell;
	char* file_device_to_use;
	char* file_modem_with_path;
	char path[50]="";				//cambia nome a variabile
	int lenght_path;
	char* last_part;
	char* detection_USB_modem;	
	char* path_device_to_use;	
	int n_modem_USB_to_check;
	char shell_command[200];			
	int i;
	char first_character[3]="";
	char* PID;
	int modem_found;
	char msg[2000];
	char pos_to_control[2];
	
	
	F_Drawings(par_Drawing,par_destination_drawing);  

	strcpy(shell_command,"find /dev -name ttyUSB* -a -type c | wc -l");	
	result_of_shell=f_result_of_shell(shell_command);
	file_device_ttyUSB = atoi(result_of_shell);

	strcpy(shell_command,"find /dev -name ttyACM* -a -type c | wc -l");	
	result_of_shell=f_result_of_shell(shell_command);
	file_device_ttyACM = atoi(result_of_shell);

	if ( file_device_ttyUSB > file_device_ttyACM )
	{
		file_device_to_use="ttyUSB";

		strcpy(shell_command,"find /dev -name ttyUSB* -type c | sort | head -n1");	
		result_of_shell=f_result_of_shell(shell_command);

		file_modem_with_path = result_of_shell;
	}	
	else if ( file_device_ttyUSB < file_device_ttyACM )
	{
		file_device_to_use="ttyACM";

		strcpy(shell_command,"find /dev -name ttyACM* -type c | sort | head -n1");	
		result_of_shell=f_result_of_shell(shell_command);

		file_modem_with_path = result_of_shell;
	}
	else
	{
		strcpy(shell_command,"clear");
		strcat(shell_command,par_destination_command_with_direction);
		system(shell_command);	

		if ( file_device_ttyUSB == 0 )
		{
			strcpy(msg,"It's not detected any USB modem. I don't find the files device for the modem.");  
		}
		else
		{
			strcpy(msg,"It's not detected any USB modem. Strange condition: there are both the files device ttyUSB and ttyACM.");  
		}

		F_WriteMessage(msg,par_destination_message);	
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

		TheFaces(2, par_destination_drawing);
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

		FrubeeInfo(par_destination_information); 		
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

		return 1;
	}

	//prende dall'ultima ricorrenza di /, fino alla fine della stringa:
	//esempio di valore di file_modem_with_path: /dev/ttyUSB0 . percorso sara' /dev/ 
	last_part=strrchr(file_modem_with_path,'/');

	lenght_path = last_part-file_modem_with_path+1;		//determino la lunghezza del percorso / ...
	strncpy (path, file_modem_with_path, lenght_path);	//...e in percorso metto i primi n caratteri di file_modem_with_path

	detection_USB_modem="NO";

	//Serve per determinare quanti sono i device da provare
	path_device_to_use=path;
	strcat(path_device_to_use,file_device_to_use);

	strcpy(shell_command,"ls ");
	strcat(shell_command,path_device_to_use);
	strcat(shell_command,"* | wc -l");		
	result_of_shell=f_result_of_shell(shell_command);
	n_modem_USB_to_check = atoi(result_of_shell);  

	for ( i=1; i<=n_modem_USB_to_check; i++ )
	{   
		sprintf(pos_to_control,"%d",i);

		// Controllo tutta la stringa contenente i ttyUSB*  
		strcpy(shell_command,"ls -C ");
		strcat(shell_command,path_device_to_use);
		strcat(shell_command,"* | awk ' { print $");
		strcat(shell_command,pos_to_control);  
		strcat(shell_command," } '");		  
		result_of_shell=f_result_of_shell(shell_command);
		modem_USB_to_check = result_of_shell;  

		//Se stacco qui il modem, all'ultimo giro, non viene rilevato
		//lo sganciamento. Ma non dovrebbero esserci problemi, perche'
		//generalmente il modem viene rilevato nei giri precedenti
		//Se stacco qui il modem, entra nella if sottostante
		//cout << "Stacca il modem" << endl;		//debug
		//sleep(5);						//debug

		strncpy (first_character, modem_USB_to_check, 1); 			
		if  (strcmp(first_character,"/") != 0) 			
		{
			strcpy(shell_command,"clear");
			strcat(shell_command,par_destination_command_with_direction);
			system(shell_command);	

			strcpy(msg,"It's not detected any USB modem. Probably the modem has been unplugged.");  
			F_WriteMessage(msg,par_destination_message);	
			strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

			TheFaces(2, par_destination_drawing);
			strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);
			strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

			FrubeeInfo(par_destination_information); 		
			strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

			return 1;
		}

		strcpy(shell_command,"echo ");
		strcat(shell_command,modem_USB_to_check);
		strcat(shell_command," > ");
		strcat(shell_command,par_file_frubee_call);
		system(shell_command);	  	

		strcpy(shell_command,"echo noauth >> ");
		strcat(shell_command,par_file_frubee_call);
		system(shell_command);	  	

		strcpy(shell_command,"rm -f ");
		strcat(shell_command,par_file_flow);
		system(shell_command);	


		strcpy(shell_command,"pppd call ");
		strcat(shell_command,process_frubee);
		strcat(shell_command," logfile ");
		strcat(shell_command,par_file_flow);
		strcat(shell_command," >> /dev/null 2>&1 &");
		system(shell_command);	  	
		
		// Verifica se serve (penso di si) - per ora lascia
		sleep(1);

		strcpy(shell_command,"grep -w -c Connect ");
		strcat(shell_command,par_file_flow);
		result_of_shell=f_result_of_shell(shell_command);
		modem_found = atoi(result_of_shell);  

		if ( modem_found == 1 )
		{
			detection_USB_modem="SI"; 

			//Potresti mettere questa informazione in /var/log/Frubee.log
			//cout << "Modem rilevato su file device " << modem_USB_to_check << endl;

			strcpy(shell_command,"ps aux | grep pppd ");
			strcat(shell_command,"| grep \"");
			strcat(shell_command,process_frubee);
			strcat(shell_command,"\" ");
			strcat(shell_command,"| awk ' { print $2 } ' | head -1");
			result_of_shell=f_result_of_shell(shell_command);
			PID = result_of_shell;  

			strcpy(shell_command,"kill -15 ");
			strcat(shell_command,PID);
			system(shell_command);	

			break;
		}
	}

	if  (strcmp(detection_USB_modem,"NO") == 0) 	
	{
		strcpy(shell_command,"clear");
		strcat(shell_command,par_destination_command_with_direction);
		system(shell_command);	
			
		strcpy(msg,"I can't figure out if the USB modem is connected or not. However has not been detected! If it's plug, then try to unplug it and replug it. But before you do, check if your connection is already active!");                    
		F_WriteMessage(msg,par_destination_message);	
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

		TheFaces(2, par_destination_drawing);
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

		FrubeeInfo(par_destination_information);
		strcpy(msg,"");  F_WriteMessage(msg,par_destination_command);

		return 1;
	}

	strcpy(shell_command,"rm -f ");
	strcat(shell_command,par_file_frubee_call);
	system(shell_command);	

	return 0;
}


int F_ManagementFile(char* par_file,  
					 char* par_file_ori,  
					 char* par_f_do_original_copy,
					 char par_destination_message[100],
					 char par_destination_command_with_direction[100])
{
	char shell_command[200];	
	int ret;
	char* result_of_shell;
	char msg[2000];

	if  (strcmp(par_f_do_original_copy,"YES") == 0) 		
	{
		// Se il file esiste già...
		strcpy(shell_command,"test -f ");
		strcat(shell_command,par_file);
		ret=system(shell_command);			
		if  ( ret == 0 ) 			
		{
			strcpy(shell_command,"cp ");
			strcat(shell_command,par_file);
			strcat(shell_command," ");
			strcat(shell_command,par_file_ori);
			ret=system(shell_command);	
			if  ( ret != 0 ) 			
			{
				strcpy(shell_command,"clear");
				strcat(shell_command,par_destination_command_with_direction);
				system(shell_command);	

				strcpy(msg,"Could not copy file ");  
				strcat(msg,par_file);  
				strcat(msg,": YOU HAVE TO BE ROOT");  

				F_WriteMessage(msg,par_destination_message);	

				return 1;
			}

	 		// Cancella il file originale  
			strcpy(shell_command,"rm -f ");
			strcat(shell_command,par_file);
			ret=system(shell_command);	
			if  ( ret != 0 ) 			
			{
				strcpy(shell_command,"clear");
				strcat(shell_command,par_destination_command_with_direction);
				system(shell_command);	

				strcpy(msg,"Could not delete file ");  
				strcat(msg,par_file);  
				strcat(msg,": YOU HAVE TO BE ROOT");  

				F_WriteMessage(msg,par_destination_message);	

				return 1;
			}
		}	
	}	

	// Crea il file par_file
	strcpy(shell_command,"printf \"\" > ");
	strcat(shell_command,par_file);
	ret=system(shell_command);	
	if  ( ret != 0 ) 
	{
		strcpy(shell_command,"clear");
		strcat(shell_command,par_destination_command_with_direction);
		system(shell_command);	

		strcpy(msg,"Could not create file ");  
		strcat(msg,par_file);  
		strcat(msg,": YOU HAVE TO BE ROOT");  

		F_WriteMessage(msg,par_destination_message);	

		return 1;
	}

	return 0;
}

void F_Temporize()
{
	//con alcuni modem, il sistema ci mette un po' per rilevarli
	//questa procedura "concede" al sistema un po' di tempo per la rilevazione
	//con i modem che vengono rilevati subito, il metodo non fa "perdere tempo":
	//trova i file device gia' al primo giro

	char* result_of_shell;
	char shell_command[200];	
	int n_attempts;
	int i;
	int file_device_ttyUSB;
	int file_device_ttyACM;	

//	int num_stringhe_ttyUSB;	//altro metodo per rilevare il modem
//	int num_stringhe_ttyACM;	//altro metodo per rilevare il modem
//	int tot_stringhe_tty;		//altro metodo per rilevare il modem


	//numero massimo di tentativi per rilevare il file device del modem:
	//considerando che fra un tentativo ed un altro passano 0,5 secondi, se
	//la procedura usa tutti i tentativi, e non trova il modem, l'utente
	//attendera' 50 secondi; se il modem e' compatibile, viene rilevato dopo 
	//circa 25 secondi (50 tentativi)	
	n_attempts=100;
	for ( i=1; i<=n_attempts; i++ )
	{   
		//Ho provato a utilizzare questo metodo per rilevare il modem:
		//il problema era che:
		//quando "dmesg" rileva il modem, il file device non e' stato ancora 
		//creato
		//il modem viene prima rilevato col dmesg comunque
		//num_stringhe_ttyUSB="dmesg | grep \"ttyUSB\" | wc -l"
		//num_stringhe_ttyACM="dmesg | grep \"ttyACM\" | wc -l"
		//tot_stringhe_tty=num_stringhe_ttyUSB+num_stringhe_ttyACM;
		//if ( tot_stringhe_tty > 0 ) { 

		//Il comando e' stato copiato da "F_DetectModem"
		strcpy(shell_command,"find /dev -name ttyUSB* -a -type c | wc -l");	
		result_of_shell=f_result_of_shell(shell_command);
		file_device_ttyUSB = atoi(result_of_shell);

		//Il comando e' stato copiato da "F_DetectModem"
		strcpy(shell_command,"find /dev -name ttyACM* -a -type c | wc -l");	
		result_of_shell=f_result_of_shell(shell_command);
		file_device_ttyACM = atoi(result_of_shell);

		//Il controllo parte dal presupposto che il sistema operativo contiene lo stesso
		//numero di file ttyUSB* e ttyACM* (ancora prima di inserire il modem)
		//Il file device e' stato trovato
		if ( file_device_ttyUSB != file_device_ttyACM ) 
		{
			break;
		}
		system("sleep 0.5");
	}
}


int F_ConnectModemUSBMobile(char* par_Operator,char* name_device_USB,bool f_par_Operator_contains_APN)
{
	//par_Operator arriva sempre valorizzato

	char* Operator="";	  			//operatore da connettere
	int type_execution_program;	
	int lenght_str_operator;
	int lenght_str_processed;
	char str_processed[30]="";
	int Drawing;

	char* modem_USB_to_check = "";
	char* f_do_original_copy;	
	char shell_command[200];
	int check_modem;
	char* result_of_shell;	
	int f_str_found;	
	char* check_carried_out;
	char* kill_pppd;
	char* f_connect;	
	char* confirmation_check_connection;
	char* PID;
	char* correct_key;
	char* PID1	;
	char* PID2	;	
	string str_typed; 	
	
	int ret;

	char* file_flow;
	char* file_frubee_chat;
	char* file_frubee_chat_ori;
	char* file_frubee_call;
	char* file_frubee_call_ori;
	char* file_ipup;
	char* file_ipup_ori;

	char* check_connection;
	char* typed;

	int f_check;		//Cambia nome


	int f_active_process_frubee;
	int i;
	char i_char[4];
	char process_frubee[10];
	int ppp_unit_number;
	char ppp_unit_number_char[4];
	char process_ppp[8];			//se lanci altri processi di pppd non con frubee
									//il valore contenuto in questa variabile potrebbe 
									//non essere corretto



	file_ipup="/etc/ppp/ip-up";
	file_ipup_ori="/etc/ppp/ip-up_ORI_bYfRubEe";


	string file_flow_tmp="/tmp/frubee_modem";
	string file_frubee_chat_tmp="/etc/ppp/frubee";
	string file_frubee_chat_ori_tmp="/etc/ppp/frubee_ORI";
	string file_frubee_call_tmp="/etc/ppp/peers/frubee";
	string file_frubee_call_ori_tmp="/etc/ppp/peers/frubee_ORI";	

	i=1;
	for(;;)
	{
		sprintf(i_char,"%d",i);
		strcpy(process_frubee,"frubee");
		strcat(process_frubee,i_char);

		strcpy(shell_command,"ps aux | grep pppd ");
		strcat(shell_command,"| grep \"");
		strcat(shell_command,process_frubee);
		strcat(shell_command,"\" ");
		strcat(shell_command,"| wc -l");
		result_of_shell=f_result_of_shell(shell_command);
		f_active_process_frubee = atoi(result_of_shell);
		if  ( f_active_process_frubee == 1 ) 	//se e' 1 vuol dire che non ci sono processi attivi		
												//quello che trova e' se stesso
		{
			file_flow_tmp=file_flow_tmp+i_char;
			file_flow=strdup(file_flow_tmp.c_str());	

			file_frubee_chat_tmp=file_frubee_chat_tmp+i_char+".chat";
			file_frubee_chat=strdup(file_frubee_chat_tmp.c_str());	

			file_frubee_chat_ori_tmp= file_frubee_chat_ori_tmp+i_char+".chat";
			file_frubee_chat_ori=strdup( file_frubee_chat_ori_tmp.c_str());	

			file_frubee_call_tmp=file_frubee_call_tmp+i_char;
			file_frubee_call=strdup(file_frubee_call_tmp.c_str());	

			file_frubee_call_ori_tmp=file_frubee_call_ori_tmp+i_char;
			file_frubee_call_ori=strdup(file_frubee_call_ori_tmp.c_str());	

			ppp_unit_number=i-1;
			sprintf(ppp_unit_number_char,"%d",ppp_unit_number);
			strcpy(process_ppp,"ppp");
			strcat(process_ppp,ppp_unit_number_char);

			break;
		}	
		i++;
	}


	char destination_drawing[100];		
	char destination_information[100];	
	char destination_message[100];	
	char destination_command[100];	
	char destination_command_with_direction[100];
	char msg[2000];


	lenght_str_operator = strlen (par_Operator);
	lenght_str_processed = strcspn(par_Operator, "_");
	strncpy (str_processed, par_Operator, lenght_str_processed); 	
	if ( lenght_str_operator == lenght_str_processed) 		
	{		
		type_execution_program=0;			//Esegue da shell 		
		Operator=par_Operator;
	}		
	else
	{		
		type_execution_program=1;	 		//Esegue da boot	
		Operator=str_processed;
	}		

	if ( type_execution_program==0 )
	{		
		strcpy(destination_drawing,"");	
		strcpy(destination_information,"");	
		strcpy(destination_message,"");	
		strcpy(destination_command,"");	
		strcpy(destination_command_with_direction,"");
	}
	else if ( type_execution_program==1 )
	{		
		strcpy(destination_drawing,"/dev/null");	
		strcpy(destination_information,"/dev/null");	
		strcpy(destination_message,"/tmp/NOCONNECT.err");			
		strcpy(destination_command,"/dev/null");	

		strcpy(destination_command_with_direction," > ");
		strcat(destination_command_with_direction,destination_command);
	}

	strcpy(shell_command,"pppd --help >> /dev/null 2>&1");
	ret=system(shell_command);			
	if  ( ret != 0 ) 			
	{
		strcpy(shell_command,"clear");
		strcat(shell_command,destination_command_with_direction);
		system(shell_command);	

		strcpy(msg,"Install \"pppd\". ");  
		strcat(msg,"It's used for the connection of mobile USB modem."); 
		F_WriteMessage(msg,destination_message);	
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);

		//
		TheFaces(2, destination_drawing);

		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
		
		FrubeeInfo(destination_information); 		
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

		return 1;
	}

	//l'ho messo qui, ma se trovi un posto migliore in cui metterlo, spostalo
	F_Temporize();

	strcpy(shell_command,"clear");
	strcat(shell_command,destination_command_with_direction);
	system(shell_command);	


	// ************************************************************	

	if (strcmp(name_device_USB,"") == 0)
	{
		//Rilevamento modem
		Drawing=1;	
		ret=F_DetectModem(modem_USB_to_check,
						process_frubee,	
						Drawing, 
						file_frubee_call, 
						file_flow,
						destination_drawing,
						destination_information,
						destination_message,
						destination_command,
						destination_command_with_direction);  
		if  ( ret != 0 ) 			
		{
			return 1;		
		}
	}
	else
	{
		string modem_USB_to_check_tmp="/dev/";
		modem_USB_to_check_tmp=modem_USB_to_check_tmp+name_device_USB;
		modem_USB_to_check=strdup(modem_USB_to_check_tmp.c_str());
	}

	//Carica APN, DNS1, DNS2 (DNS1 e DNS2 non usati)
	struct record_OperatorParameters r_OperatorParameters;
	if ( f_par_Operator_contains_APN==false )
	{
		ret=F_OperatorParameters(Operator, &r_OperatorParameters);
		if  ( ret != 0 ) 			
		{
			cout << "Connection procedure terminated with error."   << endl;	
			return 1;		
		}
	}
	else
	{
		r_OperatorParameters.Operator_APN=Operator;
	}

	// ***************gestione file_frubee_call************************
	f_do_original_copy="NO";
	ret=F_ManagementFile(file_frubee_call, 
					     file_frubee_call_ori, 
					     f_do_original_copy,
					     destination_message,
					     destination_command_with_direction);
	if  ( ret != 0 ) 	{	return 1;	}

	strcpy(shell_command,"echo ");
	strcat(shell_command,modem_USB_to_check);
	strcat(shell_command," '57600' >> ");
	strcat(shell_command,file_frubee_call);	
	system(shell_command);

	strcpy(shell_command,"echo \"connect '/usr/sbin/chat -v -e -s -f ");
	strcat(shell_command,file_frubee_chat);
	strcat(shell_command,"'\" >> ");
	strcat(shell_command,file_frubee_call);
	system(shell_command);	
	
	strcpy(shell_command,"echo 'noauth' >> ");
	strcat(shell_command,file_frubee_call);
	system(shell_command);	

	strcpy(shell_command,"echo 'defaultroute' >> ");
	strcat(shell_command,file_frubee_call);
	system(shell_command);	

	strcpy(shell_command,"echo 'debug' >> ");
	strcat(shell_command,file_frubee_call);
	system(shell_command);	

	//inserisce in automatico i DNS nel file /etc/ppp/resolv.con
	strcpy(shell_command,"echo 'usepeerdns' >> ");
	strcat(shell_command,file_frubee_call);
	system(shell_command);	


	//***************gestione file_frubee_chat*************************
	f_do_original_copy="NO";
	ret=F_ManagementFile(file_frubee_chat, 
					     file_frubee_chat_ori , 
					     f_do_original_copy,
					     destination_message,
					     destination_command_with_direction);	
	if  ( ret != 0 ) 	{	return 1;	}

	//'' \d*/
	strcpy(shell_command,"echo \"'' \\d\" >> ");
	strcat(shell_command,file_frubee_chat);
	system(shell_command);	

	// Serve per aprire il colloquio col modem (necessario)
	//'' 'ATZ'
	strcpy(shell_command,"echo \"'' 'ATZ'\" >> ");
	strcat(shell_command,file_frubee_chat);
	system(shell_command);	
	
	//Per chiamata
	//OK 'ATQ0 V1 E1 S0=0 &C1 &D2 +FCLASS=0'
	strcpy(shell_command,"echo \"OK 'ATQ0 V1 E1 S0=0 &C1 &D2 +FCLASS=0'\" >> ");		//To test the LTE modem - Comment
	//strcpy(shell_command,"echo \"OK 'ATQ0 V1 E1 S0=0'\" >> ");						//To test the LTE modem - Uncomment
	strcat(shell_command,file_frubee_chat);
	system(shell_command);	

	//OK 'AT+CGDCONT = 1,"IP","nazione.operatore"'
	strcpy(shell_command,"echo \"OK 'AT+CGDCONT = 1,\"");
	strcat(shell_command,"'\"IP\"'");  
	strcat(shell_command,","); 
	strcat(shell_command,"'\"'");  //scrive virgolette
	strcat(shell_command,r_OperatorParameters.Operator_APN);
	strcat(shell_command,"'\"'");  //scrive virgolette	  
	strcat(shell_command,"\"'\""); 
	strcat(shell_command," >> ");
	strcat(shell_command,file_frubee_chat);	
	system(shell_command);	


	//OK 'ATD*99#'
	strcpy(shell_command,"echo \"OK 'ATD\"");
	strcat(shell_command,"*99#");
	strcat(shell_command,"\"'\""); 
	strcat(shell_command," >> "); 
	strcat(shell_command,file_frubee_chat);
	system(shell_command);	

	//To test the LTE modem - Uncomment - BEGIN
	//strcpy(shell_command,"echo \"CONNECT CLIENT\" >> ");
	//strcat(shell_command,file_frubee_chat);
	//system(shell_command);	
	//To test the LTE modem - Uncomment - END


	strcpy(shell_command,"clear");
	strcat(shell_command,destination_command_with_direction);
	system(shell_command);	

	F_Drawings(2, destination_drawing);  

	sleep(9);	//e' stato messo, altrimenti il modem e' ancora occupato
				//Invece dello sleep potresti killare pppd??

	strcpy(shell_command,"rm -f ");
	strcat(shell_command,file_flow);
	system(shell_command);	


	// ******************** INIZIO CONNESSIONE *******************
	strcpy(shell_command,"pppd call ");
	strcat(shell_command,process_frubee);
	strcat(shell_command," logfile ");
	strcat(shell_command,file_flow);
	strcat(shell_command," >> /dev/null 2>&1 &");
	system(shell_command);	  	
	
	// Attendi 1 secondo prima di controllare il file di log
	sleep(1);

	//Serve per controllare se il device e' occupato da un altro processo:
	//controlla in tutto il file se c'e' il termine "locked"
	strcpy(shell_command,"grep -w -c locked ");
	strcat(shell_command,file_flow);
	result_of_shell=f_result_of_shell(shell_command);
	check_modem = atoi(result_of_shell);  
	if ( check_modem == 1  )
	{
		//Se il modem è occupato viene scritto: "Device ttyUSB2 is locked by pid 3552" 
		//(Se vuoi farlo apparire togli lo sleep di 9 secondi sopra)
		//VEDI SE LIBERARLO COL KILL
		strcpy(shell_command,"clear");
		strcat(shell_command,destination_command_with_direction);
		system(shell_command);	

		//riesci anche a visualizzarlo se premi CTRL+C mentre sta rilevando il modem
		strcpy(msg,"The modem is busy.");  
		F_WriteMessage(msg,destination_message);	
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

		TheFaces(2, destination_drawing);
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

		FrubeeInfo(destination_information); 		
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

		return 1;  
	}		

	//Aggiunto perche' il file "/tmp/frubee_modem[x]" all'inizio del ciclo e' 
	//ancora vuoto e da' l'errore (poi comunque continua)
	sleep(1);

	strcpy(shell_command,"test -f ");
	strcat(shell_command,file_ipup);
	ret=system(shell_command);			
	if  ( ret == 0 ) 			//Se il file esiste
	{
		strcpy(shell_command,"grep -w -c madEbYfRubEe ");
		strcat(shell_command,file_ipup);
		result_of_shell=f_result_of_shell(shell_command);
		f_str_found = atoi(result_of_shell);  

		if ( f_str_found == 1 )
		{
			f_do_original_copy="NO";
		}		
		else
		{
			f_do_original_copy="YES";
		}		
	}		
	else
	{
		f_do_original_copy="NO";
	}
	
	ret=F_ManagementFile(file_ipup, 
   					     file_ipup_ori , 
					     f_do_original_copy,
					     destination_message,
					     destination_command_with_direction);	
	if  ( ret != 0 ) 	{	return 1;	}

	strcpy(shell_command,"echo \"#!/bin/bash\" > ");
	strcat(shell_command,file_ipup);
	system(shell_command);	 
	
	strcpy(shell_command,"echo \"madEbYfRubEe\" >> ");
	strcat(shell_command,file_ipup);
	system(shell_command);
	
	//Cambia i permessi al file: il proprietario puo' leggere, scrivere
	//ed eseguire; gli altri non fanno niente (-rwx------) 
	strcpy(shell_command,"chmod 700 ");
	strcat(shell_command,file_ipup);
	system(shell_command);	

	//	
	check_carried_out="NO";
	kill_pppd="NO";

	char command1[200];
	char command2[200];
	char command3[200];

	strcpy(command1,"tail -n1 ");			
	strcat(command1,file_flow);			
	strcat(command1," | awk ' { print $1 } '");			

	strcpy(command2,"tail -n1 ");			
	strcat(command2,file_flow);			
	strcat(command2," | awk ' { print $2 } '");			

	strcpy(command3,"tail -n1 ");			
	strcat(command3,file_flow);			
	strcat(command3," | awk ' { print $3 } '");					


	char* c1="Connect"; 	
	char* c2="failed";	
	char* c3="Connection";	
	char* c4="terminated.";	
	char* c5="Modem";
	char* c6="hangup";
	char* c7="+CME";	
	char* c8="ERROR:";	
	char* c9="ERROR^M";	
	char* c10="Script";	
	char* c11="finished";	

	//inizio controllo connessione
	while (strcmp(check_carried_out,"NO") == 0) 
	{
		strcpy(shell_command,command1);
		result_of_shell=f_result_of_shell(shell_command);
		check_connection = result_of_shell;  


		if  (strcmp(check_connection,c1) == 0) 	
		{
			// se stacco il modem appare questa stringa: "Connect script failed"
			strcpy(shell_command,command3);		

			result_of_shell=f_result_of_shell(shell_command);
			confirmation_check_connection = result_of_shell;  

			if  (strcmp(confirmation_check_connection,c2) == 0) 
			{
				strcpy(shell_command,"clear");
				strcat(shell_command,destination_command_with_direction);
				system(shell_command);	

				strcpy(msg,"It almost seems that the modem has been unplugged!");  
				F_WriteMessage(msg,destination_message);	
				strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

				check_carried_out="YES";
				f_connect="NO";
			}
		}

		else if  (strcmp(check_connection,c3) == 0) 
		{
			strcpy(shell_command,command2);

			result_of_shell=f_result_of_shell(shell_command);
			confirmation_check_connection = result_of_shell;  

			if  (strcmp(confirmation_check_connection,c4) == 0) 
			{
				strcpy(shell_command,"clear");
				strcat(shell_command,destination_command_with_direction);
				system(shell_command);	

				strcpy(msg,"The connection was being almost made...It almost seems that the modem has been unplugged! Or check if there's credit in the SIM. Or you were wrong to choose the operator.");  
				F_WriteMessage(msg,destination_message);	
				strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

				check_carried_out="YES";
				f_connect="NO";
			}
		}

		else if  (strcmp(check_connection,c5) == 0) 
		{
			strcpy(shell_command,command2);

			result_of_shell=f_result_of_shell(shell_command);
			confirmation_check_connection = result_of_shell;  

			if  (strcmp(confirmation_check_connection,c6) == 0) 	
			{
				strcpy(shell_command,"clear");
				strcat(shell_command,destination_command_with_direction);
				system(shell_command);	

				strcpy(msg,"The modem is busy...Try to turn off the PC, unplug the modem and replug it once you turn the PC.");  
				F_WriteMessage(msg,destination_message);	
				strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

				check_carried_out="YES";
				f_connect="NO";
			}
		}	

		else if  (strcmp(check_connection,c7) == 0) 
		{
			strcpy(shell_command,command2);

			result_of_shell=f_result_of_shell(shell_command);
			confirmation_check_connection = result_of_shell;  

			if  (strcmp(confirmation_check_connection,c8) == 0)	
			{
				strcpy(shell_command,"ps aux | grep pppd ");
				strcat(shell_command,"| grep \"");
				strcat(shell_command,process_frubee);
				strcat(shell_command,"\" ");
				strcat(shell_command,"| awk ' { print $2 } ' | head -1");
				result_of_shell=f_result_of_shell(shell_command);
				PID = result_of_shell;  
				kill_pppd="SI";

				strcpy(shell_command,"clear");
				strcat(shell_command,destination_command_with_direction);
				system(shell_command);	

				strcpy(msg,"In the SIM in the modem there's a PIN code: disable it. ");  	
				strcat(msg,"Or you are using a LTE USB modem sticks. Currently I can't handle the LTE USB modem sticks.");  	

				F_WriteMessage(msg,destination_message);
				strcpy(msg,"");  F_WriteMessage(msg,destination_command);

				check_carried_out="YES";
				f_connect="NO";
			}
		}	


		//Quando col cellulare imposto il codice pin nella SIM, non spengo il 
		//cellulare e provo a connettermi con frubee.
		//Oppure collego il telefonino ed e' spento
		else if  (strcmp(check_connection,c9) == 0) 		
		{
			strcpy(shell_command,"ps aux | grep pppd ");
			strcat(shell_command,"| grep \"");
			strcat(shell_command,process_frubee);
			strcat(shell_command,"\" ");
			strcat(shell_command,"| awk ' { print $2 } ' | head -1");
			result_of_shell=f_result_of_shell(shell_command);
			PID = result_of_shell;  
			kill_pppd="SI";

			strcpy(shell_command,"clear");
			strcat(shell_command,destination_command_with_direction);
			system(shell_command);	

			strcpy(msg,"There are problems of connection. Try to turn off and turn on the modem (if mobile phone) or unplug it from the PC (if USB modem sticks).");  
			F_WriteMessage(msg,destination_message);	
			strcpy(msg,"");  F_WriteMessage(msg,destination_command);

			check_carried_out="YES";
			f_connect="NO";
		}


		//-----------------------------------------------
		//Se devi aggiungere altri controlli, mettili qui
		//-----------------------------------------------


		else if  (strcmp(check_connection,c10) == 0) 
		{
			strcpy(shell_command,command3);

			result_of_shell=f_result_of_shell(shell_command);
			confirmation_check_connection = result_of_shell;  

			//Connessione effettuata
			if  (strcmp(confirmation_check_connection,c11) == 0) 
			{
				check_carried_out="YES";
				f_connect="YES";
			}
		}

		//E' stato aggiunto perche se usciva dal ciclo per errore, non
		//riusciva a rilevare che non si era connessi se si sceglieva
		//un operatore mobile errato.
		//I tempi di connessione aggiungendo lo sleep sono rimasti invariati:
		//ma la cosa bella e' che non esce piu' dal ciclo.
		//Non ho provato a mettere sleep con tempo minore (si puo??)
		system("sleep 0.1");

	}

	//f_connect: se sbaglio operatore mobile, comunque come valore ha sempre "YES"
	if  (strcmp(f_connect,"NO") == 0) 
	{
		TheFaces(2, destination_drawing);

		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
		
		FrubeeInfo(destination_information); 		
		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

		if (strcmp(kill_pppd,"SI") == 0) 
		{
			strcpy(shell_command,"kill -15 ");
			strcat(shell_command,PID);
			system(shell_command);	
		}	

		return 1;  
	}


	//In qualche distro /etc/ppp/resolv.conf e' un symbolic link a /etc/resolv.conf
	//e pppd crea /etc/resolv.conf (non ho approfondito l'argomento)
	strcpy(shell_command,"readlink /etc/ppp/resolv.conf | wc -w");	
	result_of_shell=f_result_of_shell(shell_command);
	f_check = atoi(result_of_shell);		

	//Se il file /etc/ppp/resolv.conf e' stato creato da pppd
	if  ( f_check == 0 ) 
	{
		strcpy(shell_command,"ln -s -f /etc/ppp/resolv.conf /etc/resolv.conf");
		system(shell_command);	
	}

	strcpy(shell_command,"clear");
	strcat(shell_command,destination_command_with_direction);
	system(shell_command);	

	TheFaces(1, destination_drawing);
	strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
	strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
	strcpy(msg,"");  F_WriteMessage(msg,destination_command);		
	strcpy(msg,"");  F_WriteMessage(msg,destination_command);	


	//In questa if, potevo anche non usare "F_WriteMessage", ma lasciare "cout",
	//dato che funziona solo in shell
	if ( type_execution_program == 0 )
	{	
		cout << "To disconnect type D and press Enter" << endl;
		cin >> str_typed;   

		typed = strdup(str_typed.c_str());			
		
		//Controllo risposta dell'utente
		correct_key="NO";
		while (strcmp(correct_key,"NO") == 0)
		{
			if (strcmp(typed,"D") == 0)
			{
				correct_key="YES";
			}
			else 
			{
				strcpy(shell_command,"clear");
				strcat(shell_command,destination_command_with_direction);
				system(shell_command);	

				cout << "You typed the key " << typed << endl;
				cout << "To disconnect type D" <<  endl;
				cin >> str_typed;   

				typed = strdup(str_typed.c_str());			
			}
		}

		strcpy(shell_command,"clear");
		strcat(shell_command,destination_command_with_direction);
		system(shell_command);	

		strcpy(msg,"Disconnecting in progress...");  
		F_WriteMessage(msg,destination_command);	


		strcpy(shell_command,"ps aux | grep pppd ");
		strcat(shell_command,"| grep \"");
		strcat(shell_command,process_frubee);
		strcat(shell_command,"\" ");
		strcat(shell_command,"| awk ' { print $2 } ' | head -1");
		result_of_shell=f_result_of_shell(shell_command);
		PID1 = result_of_shell;  


		strcpy(shell_command,"ps aux | grep pppd ");
		strcat(shell_command,"| grep \"");
		strcat(shell_command,process_frubee);
		strcat(shell_command,"\" ");
		strcat(shell_command,"| awk ' { print $2 } ' | head -1");
		result_of_shell=f_result_of_shell(shell_command);
		PID2 = result_of_shell;  

		if  (strcmp(PID1,PID2) == 0) // Se sono uguali...
		{
			strcpy(shell_command,"kill -15 ");
			strcat(shell_command,PID1);
			system(shell_command);	
		}
		else		
		{	

			strcpy(shell_command,"ps aux | grep pppd ");
			strcat(shell_command,"| grep \"");
			strcat(shell_command,process_frubee);
			strcat(shell_command,"\" ");
			strcat(shell_command,"| awk ' { print $2 } ' | tail -1");
			result_of_shell=f_result_of_shell(shell_command);
			PID1 = result_of_shell;  

			strcpy(shell_command,"ps aux | grep pppd ");
			strcat(shell_command,"| grep \"");
			strcat(shell_command,process_frubee);
			strcat(shell_command,"\" ");
			strcat(shell_command,"| awk ' { print $2 } ' | tail -1");
			result_of_shell=f_result_of_shell(shell_command);
			PID2 = result_of_shell;  

			strcpy(shell_command,"kill -15 ");
			strcat(shell_command,PID1);
			system(shell_command);	
		}

		system("sleep 0.2");		//Va messo per permettere "ppp[x]" di disattivarsi
									//Funziona anche con 0.1, ma per sicurezza ho messo 0.2

		//se ppp[x] non c'e', vuol dire che è disconnesso
		strcpy(shell_command,"ifconfig ");
		strcat(shell_command,process_ppp);
		strcat(shell_command," >> /dev/null 2>&1");
		ret=system(shell_command);			
		if  ( ret == 0 ) 	
		{	  
			strcpy(msg,"...There are problems of disconnection....");  
			F_WriteMessage(msg,destination_command);	
			return 1;  
		}	  
	  
		strcpy(shell_command,"clear");
		strcat(shell_command,destination_command_with_direction);
		system(shell_command);

		strcpy(msg,"Disconnected");  
		F_WriteMessage(msg,destination_command);	

		strcpy(msg,"");  F_WriteMessage(msg,destination_command);	
	}
	
	FrubeeInfo(destination_information); 	
	strcpy(msg,"");  F_WriteMessage(msg,destination_command);	

	return 0;

}

//********** Connessione Mobile ********FINE

//********** Command-line arguments ******** INIZIO
void usage()
{

	cout << ("Frubee is a program for Internet connection\n")
	<< ("\n")
	<< ("Usage: frubee [options]\n")
	<< ("\n")
	<< ("Options:\n")
 
//	<< ("  -x,  --xxxxxxxxxxx       xxxxx xxxxxxxxx xx  xxxxx xxxxxxxx xxxx xxxxx\n")	//lunghezza massima riga	//commenta

	<< ("  --help                   Print this help and exit\n")

	<< ("  --version                Print version information and exit\n") 

	<< ("  -n,  --name-nation       Set the Nation\n") 
	<< ("                           Put a value present in the 2° column of the\n") 
	<< ("                           file \"/etc/Nations.txt\"\n") 

	<< ("  -o,  --name-operator     Set the Operator\n") 
	<< ("                           Put a value present in the 2° column (the \n") 
	<< ("                           string between #10I# and #10F# when present)\n") 
	<< ("                           of the files \n") 
	<< ("                           \"/etc/RouterIPAddressesName.txt\" or\n") 
	<< ("                           \"/etc/RouterOperatorsIPAddressesName.txt\" or\n") 
	<< ("                           \"/etc/Operators_Mobile.txt\"\n") 

	<< ("  -s,  --fourth-triplet-start\n") 
	<< ("                           Put the initial number of the fourth triplet\n")     
	<< ("                           to set the range of the IP addresses to be\n")
	<< ("                           assigned with Frubee\n")
	<< ("                           Example: frubee -s 200\n")
	<< ("                           The range of the IP addresses to be assigned\n")
	<< ("                           with Frubee is from xxx.xxx.xxx.200 to\n")
	<< ("                           xxx.xxx.xxx.254\n")
	<< ("                           Only for the connection with the router\n")

	<< ("  -e,  --fourth-triplet-end\n") 
	<< ("                           Put the final number of the fourth triplet\n")     
	<< ("                           to set the range of the IP addresses to be\n")
	<< ("                           assigned with Frubee\n")
	<< ("                           Example: frubee -e 210\n")
	<< ("                           The range of the IP addresses to be assigned\n")
	<< ("                           with Frubee is from xxx.xxx.xxx.1 to\n")
	<< ("                           xxx.xxx.xxx.210\n")
	<< ("                           Only for the connection with the router\n")

	<< ("  -U,  --name-device-usb   Put the name of the device USB to connect\n") 
	<< ("                           Only for the connection with the mobile\n") 

	<< ("  -D,  --user-dns          Put the DNS to use\n") 
	<< ("                           Only for the connection with the router\n") 

	<< ("  -A,  --user-apn          Put the APN to use\n") 
	<< ("                           Only for the connection with the mobile\n") 

	<< ("  --run-from-boot          Run from boot\n") 
	<< ("                           For use during the operating system boot you\n") 
	<< ("                           have to redirect frubee properly\n") 

	<< endl;

}

void version_and_copyright()
{
	cout << ("Frubee 2.3.1\n")
	<< ("Copyright (C) 2015-2016 Antonio Riontino\n")
	<< ("https://github.com/tone77/frubee\n")
	<< ("This program is free software: for more information, see the file named COPYING\n")
	<< endl;
}

//********** Command-line arguments ******** FINE


int main (int argc, char **argv)
{

//********** Command-line arguments ******** INIZIO

	//I followed this example:
	//http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html

	char* name_nation = "";			
	char* name_operator = "" ;
	int fourth_triplet_start = 0;
	int fourth_triplet_end = 0;
	char* name_device_USB = "";
	char* address_DNS = "";
	char* APN_operator = "";
	static int run_from_boot;		//Flag set by ‘--run-from-boot’.
	static int help_flag;			//Flag set by ‘--help’.
	static int version_flag;		//Flag set by ‘--version’.


	//If you don't pass the argument there aren't correct controls, regardless 
	//of whether the parameter accepts or not the argument
	//example: if I run
	//frubee --name-nation
	//in the shell there's
	//frubee: option '--name-nation' requires an argument
	//but the program doesn't stop


	int c;

	while (1)
	{
		static struct option long_options[] =
		{
			//These options set a flag.
			{"help",					no_argument,       &help_flag,		1},
			{"version",					no_argument,       &version_flag,	1},
			{"run-from-boot",			no_argument,       &run_from_boot,	1},

			//These options don’t set a flag.
			//We distinguish them by their indices.
			{"name-nation",				required_argument, 0, 				'n'},
			{"name-operator",			required_argument, 0, 				'o'},
			{"fourth-triplet-start",	required_argument, 0, 				's'},
			{"fourth-triplet-end",		required_argument, 0, 				'e'},
			{"name-device-usb",			required_argument, 0, 				'U'},
			{"user-dns",				required_argument, 0,				'D'},
			{"user-apn",				required_argument, 0,				'A'},
			{0, 0, 0, 0}
		};

		//getopt_long stores the option index here.
		int option_index = 0;

		c = getopt_long (argc, argv, "e:n:o:s:A:D:U:", long_options, &option_index);

		//Detect the end of the options.
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				//If this option set a flag, do nothing else now.
				if (long_options[option_index].flag != 0)
					break;
				printf ("option %s", long_options[option_index].name);
				if (optarg)
					printf (" with arg %s", optarg);
				printf ("\n");
				break;

			case 'e':
				fourth_triplet_end = atoi(optarg);
				break;

			case 'n':
				name_nation = optarg;
				break;

			case 'o':
				name_operator = optarg;
				break;

			case 's':
				fourth_triplet_start = atoi(optarg);
				break;

			case 'A':
				APN_operator = optarg;
				break;

			case 'D':
				address_DNS = optarg;
				break;

			case 'U':
				name_device_USB = optarg;
				break;

			case '?':
				//getopt_long already printed an error message.
				break;

			default:
				abort ();
		}
	}

	if (help_flag)
	{
		usage ();
		return 1;
	}

	if (version_flag)
	{
		version_and_copyright();
		return 1;
	}

	//Print any remaining command line arguments (not options).
	if (optind < argc)
	{
		printf ("non-option ARGV-elements: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		putchar ('\n');

		return 1;
	}

//********** Command-line arguments ******** FINE


	if ( fourth_triplet_start == 0 )
	{
		fourth_triplet_start=1;
	}	

	if ( fourth_triplet_end == 0 )
	{
		fourth_triplet_end=254;
	}	

	if ( ( fourth_triplet_end < 1 ) || ( fourth_triplet_start < 1 ) )
	{
		cout << "You can't set the fourth triplet less than 1 (except the 0)." << endl;	
		return 1;
	}	
	if ( ( fourth_triplet_end > 254 ) || ( fourth_triplet_start > 254 ) )
	{
		cout << "You can't set the fourth triplet higher than 254." << endl;	
		return 1;
	}	

	if ( fourth_triplet_end < fourth_triplet_start )
	{
		cout << "The fourth triplet end is less than of the fourth triplet start." << endl;	
		return 1;
	}	


	//cout << "name_nation: " << name_nation << endl; 
	//cout << "name_operator: " << name_operator << endl; 
	//cout << "fourth_triplet_start: " << fourth_triplet_start << endl; 
	//cout << "fourth_triplet_end: " << fourth_triplet_end << endl; 
	//cout << "name_device_USB: " << name_device_USB << endl; 
	//cout << "run_from_boot: " << run_from_boot << endl; 
	//cout << "address_DNS: " << address_DNS << endl; 
	//cout << "APN_operator: " << APN_operator << endl; 


	//run_from_boot
	//	NOTE
	//
	//	Nella parte in comune (indipendentemente da f_connection_type=1 o 
	//	f_connection_type=2, quindi fino a "if ( f_connection_type == 1 )") 
	//	il file "/tmp/NOCONNECT.err" non viene mai creato, ad eccezione per il 
	//	controllo della presenza di "dialog" e nella creazione del file "/var/log/Frubee.log"
	//
	//	Parte riguardante f_connection_type=1 o f_connection_type=2
	//	Il file "/tmp/NOCONNECT.err" se connessione 
	//	con router: viene creato sia da boot che no
	//	con mobile: viene creato solo se lanciato da boot
	//				0 : Non esegue da boot (si presuppone che sia lanciato 
	//					da shell a mano). Mostra a video l'esecuzione di frubee
	//				1 : Esegue da boot (si presuppone che sia lanciato durante l'avvio
	//					del sistema operativo. Non mostra a video l'esecuzione di frubee
	//					Per controllare se la procedura si e' connessa, va controllata
 	//					l'esistenza del file "/tmp/NOCONNECT.err".
 	//							Non esiste: connessione avvenuta
 	//							Esiste: connessione non avvenuta



	char shell_command[1000];	
	char* result_of_shell;
	int ret;
	char* cod_nation;			//andrebbe  bene anche int, ma per comodita' di cast l'ho messa cosi'
	char* name_operator_with_nation;
	int f_connection_type;
	char String_Boot[60];
	char str_operator[100];
	char DNS1[20];
	char DNS2[20];
	char msg[2000];

	char* IPAddressRouter;
	bool f_connection;
	char* IPAddressClient;
	bool f_search_router;
	bool f_par_Operator_contains_APN;


	//Crea il file log /var/log/Frubee.log
	//Gestiscilo in successive versioni.
	//Per ora serve solo per verificare se si lancia frubee come root
	strcpy(shell_command,"echo 'Hello Frubee ! ! !' > /var/log/Frubee.log");
	ret=system(shell_command);	
	if ( ret != 0 )
	{
		strcpy(shell_command,"echo ");
		strcat(shell_command,"\"It isn't possible to run the program. You have to be root.\"");
		strcat(shell_command," > /tmp/NOCONNECT.err");	
		system(shell_command);
		system("cat /tmp/NOCONNECT.err");

		cout << "Connection procedure terminated with error."   << endl;	
		return 1;
	}	

	//Per far funzionare frubee basta cancellare solo il file /tmp/SelectedOperator.txt
	//Il file /tmp/frubee_modem[x] viene cancellato in F_ConnectModemUSBMobile
	strcpy(shell_command,"rm -f /tmp/file_selected_nation.txt rm -f /tmp/file_selected_operator.txt rm -f /tmp/PhraseSelectOperator.txt rm -f /tmp/SelectedNation.txt rm -f /tmp/Operators_tmp.txt rm -f /tmp/router_IP_addresses_operators_tmp.txt rm -f /tmp/router_IP_addresses_tmp.txt rm -f /tmp/RouterIPAddresses_tmp.txt rm -f /tmp/router_operators_tmp.txt rm -f /tmp/router_tmp.txt rm -f /tmp/SelectNation rm -f /tmp/SelectOperator ");
	system(shell_command);	

	strcpy(shell_command,"rm -f /tmp/NOCONNECT.err rm -f /tmp/SelectedOperator.txt rm -f /tmp/TypeSelectedOperator.txt");
	system(shell_command);	

	if (strcmp(APN_operator,"") == 0)
	{

	//da qui indenta	
	if ( (strcmp(name_nation,"") == 0) || (strcmp(name_operator,"") == 0) )	
	{
		strcpy(shell_command,"dialog --help >> /dev/null 2>&1");
		ret=system(shell_command);			
		if  ( ret != 0 ) 			
		{
			strcpy(shell_command,"echo ");
			strcat(shell_command,"Install \"dialog.\" ");
			strcat(shell_command,"It\"'\"s used for the selection mask of the nation and of the operator.");
			strcat(shell_command," > /tmp/NOCONNECT.err");	
			system(shell_command);
			system("cat /tmp/NOCONNECT.err");

			cout << "Connection procedure terminated with error."   << endl;	
			return 1;
		}
	}

	if (strcmp(name_nation,"") == 0)
	{
		//crea lo script /tmp/SelectNation (per l'elenco nazioni, legge file /etc/Nations.txt)
		ret=F_CreatesScriptSelectNation();			
		if  ( ret != 0 ) 			
		{
			cout << "Connection procedure terminated with error."   << endl;	
			return 1;
		}

		//Apre maschera selezione Nazione
		//crea file /tmp/file_selected_nation.txt (appena viene lanciato lo script 
		//il file c'è già...viene riempito una volta scelta la nazione)
		strcpy(shell_command,". /tmp/SelectNation");		
		system(shell_command);		

		strcpy(shell_command,"echo \"\" >> /tmp/file_selected_nation.txt");
		system(shell_command);		

		strcpy(shell_command,"cat /tmp/file_selected_nation.txt");		
		result_of_shell=f_result_of_shell(shell_command);
		name_nation=result_of_shell;
	}


	ret=F_CreatesFileSelectedNation(name_nation);			
	if  ( ret != 0 ) 			
	{
		cout << "Connection procedure terminated with error."   << endl;	
		return 1;
	}

	strcpy(shell_command,"cat /tmp/SelectedNation.txt");			
	result_of_shell=f_result_of_shell(shell_command);
	cod_nation=result_of_shell;



	//***************************************************************************
	//***************************************************************************
	//Crea i file 
	//   /tmp/router_operators_tmp.txt: servira' per visualizzare anche i router "degli operatori"
	//   /tmp/router_IP_addresses_operators_tmp.txt
	ret=F_CreatesFileRouterTmp(cod_nation,1);
	if  ( ret != 0 ) 			
	{
		cout << "Connection procedure terminated with error."   << endl;	
		return 1;
	}

	//Crea i file 
	//   /tmp/router_tmp.txt che servira' per visualizzare anche i router (marche)
	//   /tmp/router_IP_addresses_tmp.txt
	ret=F_CreatesFileRouterTmp(cod_nation,2);
	if  ( ret != 0 ) 			
	{
		cout << "Connection procedure terminated with error."   << endl;	
		return 1;
	}

	//Crea file da far leggere a F_FindIPAddressRouter
	strcpy(shell_command,"cat /tmp/router_IP_addresses_operators_tmp.txt > /tmp/RouterIPAddresses_tmp.txt");
	system(shell_command);	

	strcpy(shell_command,"cat /tmp/router_IP_addresses_tmp.txt >> /tmp/RouterIPAddresses_tmp.txt");
	system(shell_command);	


	//file /tmp/Operators_tmp.txt
	//Nella seconda colonna contiene i valori della 2° colonna dei file
	//	/etc/RouterIPAddressesName.txt
	//	/etc/RouterOperatorsIPAddressesName.txt
	//	/etc/Operators_Mobile.txt
	strcpy(shell_command,"cat /tmp/router_operators_tmp.txt > /tmp/Operators_tmp.txt");
	system(shell_command);	

	strcpy(shell_command,"cat /tmp/router_tmp.txt >> /tmp/Operators_tmp.txt");
	system(shell_command);	


	//file /etc/Operators_Mobile.txt
	// 		- se non e' presente il file vengono mostrati solo i router
	// 		- se e' presente, mostra anche le connessioni "mobile"
	//		  se modifichi la lunghezza del tracciato "/etc/Operators_Mobile.txt", aggiorna 
	//        la variabile "lenght_row"  (ora e' 116)
	strcpy(shell_command,"test -f ");
	strcat(shell_command,"/etc/Operators_Mobile.txt");
	ret=system(shell_command);			
	if  ( ret == 0 )
	{
		strcpy(shell_command,"cat ");			
		strcat(shell_command,"/etc/Operators_Mobile.txt >> /tmp/Operators_tmp.txt");
		system(shell_command);
	}

	if (strcmp(name_operator,"") == 0)
	{
		ret=F_CreatesScriptSelectOperator(cod_nation);			
		if  ( ret != 0 ) 			
		{
			cout << "Connection procedure terminated with error."   << endl;	
			return 1;
		}

		//Apre maschera selezione operatore
		strcpy(shell_command,". /tmp/SelectOperator");		
		system(shell_command);	

		strcpy(shell_command,"echo \"\" >> /tmp/file_selected_operator.txt");
		system(shell_command);	

		strcpy(shell_command,"cat /tmp/file_selected_operator.txt");		
		result_of_shell=f_result_of_shell(shell_command);

		//"name_operator" puo' contenere:
		//Operatore Telefonico: file "/etc/Operators_Mobile.txt", 2° colonna
		//Marca Router: 
		//   file /etc/RouterOperatorsIPAddressesName.txt, 2° colonna
		//   file /etc/RouterIPAddressesName.txt         , 2° colonna
		name_operator=result_of_shell;
	}

	ret=F_CreatesFileSelectedOperator(name_operator);			
	if  ( ret != 0 ) 			
	{
		cout << "Connection procedure terminated with error."   << endl;	
		return 1;
	}

	strcpy(shell_command,"cat /tmp/SelectedOperator.txt");		
	result_of_shell=f_result_of_shell(shell_command);
	name_operator_with_nation=result_of_shell;

	strcpy(shell_command,"cat /tmp/TypeSelectedOperator.txt");		
	result_of_shell=f_result_of_shell(shell_command);
	f_connection_type=atoi(result_of_shell);
	//fino a qui indenta


	}
	else
	{
		f_connection_type=1;
	}



	//la stringa "__ForBOOT!" viene aggiunta sia per connessione con router
	//che mobile. Per ora con connessione con router non viene considerata.
	strcpy(String_Boot,"__ForBOOT!");
	if (strcmp(APN_operator,"") == 0)
	{
		strcpy(str_operator,name_operator_with_nation);
		f_par_Operator_contains_APN=false;
	}
	else
	{
		strcpy(str_operator,APN_operator);
		f_par_Operator_contains_APN=true;
	}

	if ( run_from_boot == true )
	{
		strcat(str_operator,String_Boot);
	}

	if ( f_connection_type == 1 )
	{
		strcpy(shell_command,"ifconfig eth0 0.0.0.0 >> /dev/null 2>&1");
		ret=system(shell_command);			
		if ( ret != 0 ) 	
		{
			//cout << "No network card detected."   << endl;
		}

		ret=F_ConnectModemUSBMobile(str_operator,name_device_USB,f_par_Operator_contains_APN);			
		if  ( ret != 0 ) 			
		{
			return 1;
		}
	}

	else if ( f_connection_type == 2 )
	{
		strcpy(shell_command,"ifconfig eth0 0.0.0.0 >> /dev/null 2>&1");
		ret=system(shell_command);			
		if ( ret != 0 ) 	
		{	  
			strcpy(shell_command,"echo ");
			strcat(shell_command,"\"1) CONNECTION ERROR: No network card detected\"");
			strcat(shell_command," > /tmp/NOCONNECT.err");	
			system(shell_command);

			system("cat /tmp/NOCONNECT.err");
			cout << "Connection procedure terminated with error."   << endl;	
			return 1;
		}	

		strcpy(msg,"Connection in progress...");
		cout <<  msg  << endl;			

		strcpy(shell_command,"ifconfig eth0 up");
		ret=system(shell_command);			
		if ( ret != 0 ) 	
		{	  
			//errori che ho rilevato se non c'e' l'interfaccia di rete o c'e' e non la rileva:
			//"ifconfig eth0" puo' dare i seguente errori:
			//ifconfig: SIOCGIFFLAGS: No such device
			//ifconfig: eth0: error fetching interface information: Device not found

			strcpy(shell_command,"echo ");
			strcat(shell_command,"\"2) CONNECTION ERROR: No network card detected\"");
			strcat(shell_command," > /tmp/NOCONNECT.err");	
			system(shell_command);

			system("cat /tmp/NOCONNECT.err");
			cout << "Connection procedure terminated with error."   << endl;	
			return 1;
		}	  

		f_search_router=true;
		f_connection=false;
		while (f_connection == false)
		{
			if  ( f_search_router == true )		
			{
				//gia' al secondo giro non serve cercare il router, perche' e' stato gia'
				//trovato al primo giro
				ret=F_FindIPAddressRouter(name_operator_with_nation, IPAddressRouter);			
				if  ( ret != 0 ) 			
				{
					system("cat /tmp/NOCONNECT.err");
					cout << "Connection procedure terminated with error."   << endl;	
					return 1;
				}
				else
				{
					strcpy(shell_command,"echo \"nameserver ");
					if (strcmp(address_DNS,"") != 0) 
					{
						strcat(shell_command,address_DNS);	
					}
					else
					{
						strcat(shell_command,IPAddressRouter);	
					}						
					strcat(shell_command,"\" > /etc/resolv.conf");						
					system(shell_command);	
				}
			}

			ret=F_FindIPAddressFree(IPAddressRouter,fourth_triplet_start,fourth_triplet_end);
			if  ( ret != 0 ) 			
			{
				system("cat /tmp/NOCONNECT.err");
				cout << "Connection procedure terminated with error."   << endl;	
				return 1;
			}
			fourth_triplet_start++;

	//INVECE CHE IN FILE, FAI GESTIONE COME ROUTER
	strcpy(shell_command,"cat /tmp/IPAddressFree.txt");		
	result_of_shell=f_result_of_shell(shell_command);
	IPAddressClient=result_of_shell;

			//cout << "TEST - Router e indirizzo IP libero trovati. Spegni router" << endl;		//debug
			//sleep(8);														//debug

			ret=F_RouterConnection(IPAddressRouter,IPAddressClient);			
			//se entra qui:
			//	-Si e' perso il collegamento col router
			//		Potrebbe essere spento
			//	-Concorrenza (piu' probabile)
			//		Questo client e' in concorrenza con un un altro client per 
			//		l'assegnazione dell'indirizzo IP "IPAddressClient".
			//		"IPAddressClient" potrebbe essere gia' stato assegnato ad un altro client.
			//		Puo' capitare (non ho approfondito) che entra qui anche se 
			//		l'indirizzo IP "IPAddressClient" non e' stato assegnato ad un altro client.
			if  ( ret != 0 ) 			
			{
				cout <<  "Phase 1: resolution conflict with other clients for the IP address " << IPAddressClient << endl;

				f_search_router=true;

				strcpy(shell_command,"ifconfig eth0 0.0.0.0");		
				system(shell_command);	

				continue;
			}

			strcpy(shell_command,"ping -c1 ");
			strcat(shell_command,IPAddressRouter);				
			strcat(shell_command," >> /dev/null");
			ret=system(shell_command);	
			if  ( ret == 0 )		
			{	
				f_connection=true;
			}
			else		//Se un altro client ha lo stesso indirizzo IP
			{		
				cout <<  "Phase 2: resolution conflict with other clients for the IP address " << IPAddressClient << endl;

				//Raramente il ping soprastante non va a buon fine su un indirizzo
				//IP non usato da nessun'altro client ed entra qui. Quindi non viene
				//assegnato al client l'indirizzo IP libero, ma la procedura fa un altro
				//giro

				f_search_router=false;

				strcpy(shell_command,"ifconfig eth0 0.0.0.0");		
				system(shell_command);	
			}
		}

		cout << "--------------------------------" << endl;
		cout << "Connection made"     << endl;
		cout << "IP Address Router: " << IPAddressRouter << endl;
		cout << "IP Address Client: " << IPAddressClient << endl;
		cout << "--------------------------------" << endl;

	}

	//se f_connection_type == 1 e run_from_boot=0
	//e la connessione avviene correttamente arriva qui solo dopo essersi disconnessi
	return 0;

}
