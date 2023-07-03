#!/usr/bin/env bash

RULES_FILE=$1
RESULT_FILE=$2
CHECKER_TOOL=$3
FALCO_DOCKER_IMAGE=$4

rm -f $RESULT_FILE
touch $RESULT_FILE

cur_branch=`git rev-parse HEAD`
echo Current branch is \"$cur_branch\"
echo Checking version for $RULES_FILE...
cp $RULES_FILE tmp_rule_file.yaml

rules_name=`echo $RULES_FILE | sed -re 's/rules\/(.*)_rules\.yaml/\1/'`
echo Searching tag with prefix prefix \"$rules_name-rules-\"...
latest_tag=`git describe --match="$rules_name-rules-*.*.*" --exclude="$rules_name-rules-*.*.*-*" --abbrev=0 --tags $(git rev-list --tags="$rules_name-rules-*.*.*" --max-count=1)`

if [ -z "$latest_tag" ]
then
    echo Not previous tag has been found
    exit 0
else
    echo Most recent tag found is \"$latest_tag\"
fi

git checkout tags/$latest_tag
$CHECKER_TOOL \
    compare \
    --falco-image=$FALCO_DOCKER_IMAGE \
    -l $RULES_FILE \
    -r tmp_rule_file.yaml \
1>tmp_res.txt
git switch --detach $cur_branch

echo '##' $RULES_FILE >> $RESULT_FILE
echo Comparing \`$cur_branch\` with latest tag \`$latest_tag\` >> $RESULT_FILE
echo "" >> $RESULT_FILE
if [ -s tmp_res.txt ]
then
    cat tmp_res.txt >> $RESULT_FILE
else
    echo "No changes detected" >> $RESULT_FILE
fi
echo "" >> $RESULT_FILE

rm -f tmp_rule_file.yaml
rm -f tmp_res.txt
