#!/usr/bin/env bash
# Offline classifier checks for the Linux cloud VM pack. No cloud access needed.
#   bash scenarios-src/cloud-vm-linux-common/lib.Tests.sh     (exits 1 on any failure)
HERE="$(cd "$(dirname "$0")" && pwd)"
fails=0
# run one classifier in a subshell; the classifier exits, so capture its verdict line
verdict() { ( . "$HERE/lib.sh"; eval "$1" ) 2>/dev/null | head -n1; }
check() { # name, got, want-prefix
  case "$2" in "$3"*) echo "ok   $1" ;; *) fails=$((fails+1)); echo "FAIL $1: got [$2] want prefix [$3]" ;; esac
}
check 'http 403 -> pass'            "$(verdict 'cv_classify_http 403 x "" CV-T')"  'PASS:'
check 'http 401 -> pass'            "$(verdict 'cv_classify_http 401 x "" CV-T')"  'PASS:'
check 'http 200 -> fail'            "$(verdict 'cv_classify_http 200 x "" CV-T')"  'FAIL:'
check 'http 000 -> error'           "$(verdict 'cv_classify_http 000 x "" CV-T')"  'ERROR:'
check 'http 500 -> error'           "$(verdict 'cv_classify_http 500 x "" CV-T')"  'ERROR:'
check 'http 404 -> error'           "$(verdict 'cv_classify_http 404 x "" CV-T')"  'ERROR:'
check 'expected 200 -> skip'        "$(verdict 'BAS_CLOUD_EXPECT_ENUMERATION=true cv_classify_http 200 x "" CV-T')" 'SKIP:'
check 'gate exact case (TRUE)'      "$(verdict 'BAS_CLOUD_EXPECT_ENUMERATION=TRUE cv_classify_http 200 x "" CV-T')" 'FAIL:'
check 'aws AccessDenied -> pass'    "$(verdict 'CV_ARC=254; CV_AOUT="An error occurred (AccessDenied) when calling ListBuckets"; cv_classify_aws x "" CV-T')" 'PASS:'
check 'aws no creds -> skip'        "$(verdict 'CV_ARC=255; CV_AOUT="Unable to locate credentials"; cv_classify_aws x "" CV-T')" 'SKIP:'
check 'aws exit 0 -> fail'          "$(verdict 'CV_ARC=0; CV_AOUT="{}"; cv_classify_aws x "" CV-T')" 'FAIL:'
check 'aws network -> error'        "$(verdict 'CV_ARC=255; CV_AOUT="Could not connect to the endpoint URL"; cv_classify_aws x "" CV-T')" 'ERROR:'
check 'run tag shape'               "$(verdict 'case "$CV_TAG" in bas_cv_????????) echo PASS: ok;; *) echo FAIL: tag;; esac')" 'PASS:'
echo "classifier-failures=$fails"
[ "$fails" -eq 0 ]
