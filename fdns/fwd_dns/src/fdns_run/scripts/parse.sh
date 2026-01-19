#!/bin/sh

function err()
{
    echo "$1" && exit 1;
}

function parse_option()
{
    echo 1 |awk '{printf("\n\n===========================option config================================\n")}';
    #require keys
    local keys="vip_0 vip_1 vEth0_ip vEth1_ip control query_log_level answer_log_level server_log_level attack_log_level"

    #option
    local options="out0_ip out1_ip  port0_dst_mac port1_dst_mac"

    local data=`sed -n "/^options/,/^}/ p" $1`
    echo $data|awk -v ks="$keys" -v options="$options" -v file="$2" 'BEGIN{optval_on = 0;}{
        split(ks,keys," ");
        for(i = 1; i <= NF; i++){
            for(k in keys){
                if($i == keys[k] ){
                    val[keys[k]] = $(i + 1)
                    i++;
                }
        
            }
        }

        split(options,optkeys," ");
                
        for(i = 1; i <= NF; i++){
            for(k in optkeys){
                if($i == optkeys[k] ){
                    valopt[optkeys[k]] = $(i + 1)
                    i++;
                    optval_on = 1;
                }
        
            }
        }

    }END{
            err=0
            for(k in keys){
                if(val[keys[k]]){
                    printf("%-15s\t%-50s\n",keys[k],val[keys[k]])
                }else{
                    err++
                    printf("%-15s\tnot found error!\n",keys[k]);
                }
            }

            
            if(optval_on){
                for(k in optkeys){
                    
                    if(valopt[optkeys[k]]){
                        printf("%-15s\t%-50s\n",optkeys[k],valopt[optkeys[k]])
                    }else{
                        err++
                        printf("[==== ERROR ====] : ST3 mode on , but %-15s\tnot found error!\n",optkeys[k]);
                    }
                }
            }

            if(err == 0){
                for(k in keys){
                    if(keys[k] == "control"){
                        split(val[keys[k]],bind,":");
                        printf("bind_addr = %s\n",bind[1]) >> file;
                        printf("bind_port = %s\n",bind[2]) >> file;
                    }else if(keys[k] == "vip_0"){
                        printf("vip_0 = %s\n",val[keys[k]]) >> file;
                    }else if(keys[k] == "vip_1"){
                        printf("vip_1 = %s\n",val[keys[k]]) >> file;
                    }else if(keys[k] == "vEth0_ip"){
                        printf("%s = %s\n",keys[k],val[keys[k]]) >> file
                        if(!optval_on)
                            printf("port0_ip = %s\n",val[keys[k]]) >> file;
                    }else if(keys[k] == "vEth1_ip"){
                        printf("%s = %s\n",keys[k],val[keys[k]]) >> file
                        if(!optval_on)
                            printf("port1_ip = %s\n",val[keys[k]]) >>file;
                    }else
                                            printf("%s = %s\n",keys[k],val[keys[k]]) >> file
                }

                if(optval_on){
                    for(k in optkeys){
                        if(optkeys[k] == "out0_ip"){
                            printf("port0_ip = %s\n",valopt[optkeys[k]]) >> file;
                        }else if(optkeys[k] == "out1_ip"){
                            printf("port1_ip = %s\n",valopt[optkeys[k]]) >>file;
                        }else
                             printf("%s = %s\n",optkeys[k],valopt[optkeys[k]]) >> file
                    }
                }
            }
            

    }'
    


    rm -f .sys.nic.conf
    cp .sys.nic.conf.origin .sys.nic.conf
    
    if [ ! -f "$2" ] ; then
        echo "$2 not complete..exit"
        exit 1
    fi
    echo "========"
    cat $2;
    echo "========"

    grep port $2|grep _ip >>.sys.nic.conf 2>&1
    grep vEth $2|grep _ip >>.sys.nic.conf 2>&1
    grep port $2|grep dst_mac >>.sys.nic.conf 2>&1
    grep vip_ $2 >>.sys.nic.conf 2>&1
    
    cp .sys.system.conf.origin .sys.system.conf
    grep bind_ $2 >>.sys.system.conf
    grep log_level $2 >> .sys.system.conf
    
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
    
            if($i ~/vgroup/){
                if($i == "vgroup"){
                    i++;
                    if($i != "{"){
                        err++
                        printf("vgroup format error in %s", vname[v]);
                    }
                    i++;
                }else if($i == "vgroup{"){
                    i++;
                }
                for(;i <= NF; i++){
                    if($i == "}")
                        break;
                        group=$i;
                        if(vgroup[v] == "")
                            vgroup[v]= group;
                        else
                            vgroup[v]= vgroup[v]","group
                }
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

                for(;i <= NF; i++){
                    if($i == "}")
                        break;
                    fwders = $i":51,"$i":52,"$i":53,"$i":54,"$i":55,"$i":56,"$i":57,"$i":58"
                    fwders = $i":53"
                    if($i ~/:/){
                        fwders= $i;
                    }

                    if(forwarders[v] == "")
                        forwarders[v]= fwders;
                    else
                        forwarders[v]= forwarders[v]","fwders
                }

                
            }
            
            if($i ~/}/){
                data_begin = 0;
            }
        }
    }END{
        vlist="viewlist = "
        for(i = 1 ; i <= v; i ++){
            printf("======view %d=======\n",i);
            printf("view        :%-24s\n",vname[i]);
            printf("backup      :%-25s\n",backup[i]);
            printf("vgroup      :%-25s\n",vgroup[i]);
            printf("forwarders  :%-100s\n",forwarders[i]);
            if(i == 1){
                vlist=vlist""vname[i];
            }else
                vlist=vlist","vname[i];
        }
        if(err == 0){
            printf("%s\n",vlist) > file;
            for(i = 1; i <=v ; i++){
                printf("%s__vgroup = %s\n",vname[i],vgroup[i]) >> file;
                printf("%s = %s\n",vname[i],forwarders[i]) >> file;
                printf("%s__backup = %s\n",vname[i],backup[i]) >> file;
                printf("\n\n") >> file;
            }
        }
    }'

    cp .sys.view.conf.origin .sys.view.conf
    cat "$2" >> .sys.view.conf
}

function run()
{
    echo "-----------------base is $BASE -----------------------"
    cd $BASE/etc/
    #$1 file
    #delete comments
    sed 's/[#;].*//g' $1 > $1.tmp

    OPFILE=".option"
    rm -f $OPFILE
    parse_option "$1.tmp"  "$OPFILE"
    rm -f $OPFILE

    VIEWFILE=".views"
    rm -f $VIEWFILE
    parse_view "$1.tmp" "$VIEWFILE"
    rm -f $VIEWFILE
    rm -f $1.tmp

    cat .sys.nic.conf >.fwd_dns.conf
    cat .sys.system.conf >>.fwd_dns.conf
    cat .sys.view.conf >>.fwd_dns.conf  
    rm -f .sys.nic.conf
    rm -f .sys.system.conf
    rm -f .sys.view.conf    
    cd $BASE
}

run $@

