cv_az_init CV-LE32
acct=$(cv_env BAS_CLOUD_TEST_STORAGE_ACCOUNT)
[ -n "$acct" ] || cv_done skip "no test storage account configured (BAS_CLOUD_TEST_STORAGE_ACCOUNT); use a synthetic-data account only" CV-LE32
cv_az_token "$CV_RES_STORAGE"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for Azure Storage (no identity attached to this VM)" CV-LE32
cv_http GET "https://$acct.blob.core.windows.net/?comp=list" "$CV_TOKEN" '' 2021-08-06
n=$(printf '%s' "$CV_HBODY" | grep -o '<Container>' | wc -l)
echo "EXEC T1530: blob container names listed on the test account only; http=$CV_HCODE containers=$n. No blob was read."
cv_classify_http "$CV_HCODE" 'Azure Blob container access' BAS_CLOUD_EXPECT_ENUMERATION CV-LE32
