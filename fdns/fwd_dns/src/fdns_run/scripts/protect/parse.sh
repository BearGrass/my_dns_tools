#!/bin/sh

function err()
{
	echo "$1" && exit 1;
}

function parse_view()
{
	echo 1|awk '{printf("\n\n===========================view config================================\n")}';
	local data=`sed -n '/view/,/^}/ p' $1`;
	echo $data|awk -v file="$2" 'BEGIN{v=0;}{
		for(i = 1 ; i <= NF ; i++){

			if($i ~/view/){
				tmp = $(i+1)
				split(tmp,tmp2,"\"");
				vname[++v] = tmp2[2]
				i++
				data_begin = 1;
				continue;
			}
	
			if(data_begin == 0)
				continue;
	
			if($i ~/backup/) {
				tmp = $(i+1)
				split(tmp,tmp2,"\"");
				backup[v] = tmp2[2]
				i++;
				continue;
			}
	
			if($i ~/aclfile/){
				aclfile[v] = $(i+1)
				i++;
				continue;
			}
		
			if($i ~/forwarders/){
				if($i == "forwarders"){
					i++;
					if($i != "{"){
						err++
						printf("forwarders format error in %s",vname[v]);
					}
					i++;
				}else if($i == "forwarders{"){
					i++;
				}
				
				
				forwarders[v]="(\"";

				for(;i <= NF; i++){
					if($i == "}")
						break;
					fwders = $i
					if($i ~/:/){
						split($i,host,":")
						fwders= host[1];
					}

					forwarders[v]= forwarders[v]" "fwders
				}
				forwarders[v]= forwarders[v]" \")"

				
			}
			
			if($i ~/}/){
				data_begin = 0;
			}
		}
	}END{
		vlist="viewlist=(\""
		for(i = 1 ; i <= v; i ++){
			printf("======view %d=======\n",i);
			printf("view		:%-24s\n",vname[i]);
			printf("backup 		:%-25s\n",backup[i]);
			printf("aclfile		:%-25s\n",aclfile[i]);
			printf("forwarders	:%-100s\n",forwarders[i]);
			if(i == 1){
				vlist=vlist""vname[i];
			}else
				vlist=vlist" "vname[i];
		}
		vlist=vlist"\")"
		if(err == 0){
			printf("%s\n",vlist) > file;
			for(i = 1; i <=v ; i++){
				printf("%s=%s\n",vname[i],forwarders[i]) >> file;
			}
		}
	}'

}

function run()
{
	#$1 file
	#delete comments
	sed 's/[#;].*//g' $1 > $1.tmp


	VIEWFILE="$2"
	rm -f $VIEWFILE
	parse_view "$1.tmp" "$VIEWFILE"
	rm -f $1.tmp
}

run $@
