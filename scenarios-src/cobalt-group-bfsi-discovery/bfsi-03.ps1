# Cobalt Group BFSI - ATM switch discovery (bfsi-03)
$res = Invoke-AtmSwitchDiscovery
Complete-BfsiStep $res 'bfsi-03'
