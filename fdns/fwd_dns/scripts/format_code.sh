find . -name "*.c" | xargs dos2unix
find . -name "*.c" | xargs indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4 -cli4 -d0 -di1 -nfc1 -i4 -ip0 -l110 -lp -npcs -nprs -npsl -sai -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts4 -il0 -nut -bli0 -l80
