#!/bin/bash

# ARGUMENT #1
# ip address of phone (if connecting via docker)
# go to settings > wifi > IP address

# ARGUMENT #2
# apk file system names:
# 1) jakhar.aseem.diva
# 2) com.android.insecurebankv2

ipadd=$1
apk=$2
drozer_c="drozer console connect --server $ipadd -c"

# output app stats
$drozer_c "run app.package.info -a $apk"

# output attack surface
$drozer_c "run app.package.attacksurface $apk"

# iterate through activities
echo checking activities...
$drozer_c "run app.activity.info -a $apk" > tmp_file
cat tmp_file
while read line; do
  if grep -q "$apk." <<< "$line"; then
    echo starting $line...
    $drozer_c "run app.activity.start --component $apk $line"
    sleep 5
  fi
done < tmp_file

#***IMPLICATION(S)***#
# will reveal buggy screens upon opening
# can also reveal accessible screens
#********************#

# check content providers for SQL injection
echo checking for sql injection...
$drozer_c "run scanner.provider.injection -a $apk" > tmp_file
echo
cat tmp_file

#***POTENTIAL DIRECTION***#
# use findings to perform SQL injection for PoC
#*************************#

# check content providers for info exposure
echo checking content providers...
$drozer_c "run scanner.provider.finduris -a $apk" > tmp_file
cat tmp_file
while read line; do
  if grep -q "Able to Query" <<< "$line"; then
    cp="${line:14:${#line}-1}"
    echo checking $cp for exposing info...
    $drozer_c "run app.provider.query $cp"
    $drozer_c "run scanner.provider.sqltables -a $cp"
    sleep 5
  fi
done < tmp_file

#***POTENTIAL DIRECTION***#
# use info from exposed content providers to see if information
# can be inserted; reveals integrity concern in app
# this can be done with drozer `insert` module
# ex) run app.provider.insert $content_path --integer _id 3 --string user Tom 
#                             --string pass 1234 --string email tom@gmail.com
#*************************#

# reveal broadcast receivers
echo checking broadcast receivers...
$drozer_c "run app.broadcast.info -a $apk" > tmp_file
cat tmp_file

#***POTENTIAL DIRECTION***#
# use findings to send broadcast information 
# this can be done with drozer `send` module
# ex) run app.broadcast.send --component $comp --action $action --data-uri tel:123456789 
# use findings to sniff intents
# this can be done with drozer `sniff` module
# ex) run app.broadcast.sniff --action android.intent.action.BATTERY_CHANGED
#*************************#

# reveal services
echo checking services...
$drozer_c "run app.service.info -a $apk" > tmp_file
cat tmp_file

#***POTENTIAL DIRECTION***#
# use findings to take advantage of unprotected started services
# this can be done with drozer `start` module
# ex) run app.service.start --action com.android.clipboardsaveservice.CLIPBOARD_SAVE_SERVICE
#*************************#
