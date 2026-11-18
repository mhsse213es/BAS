# CSCRF-ID-07: MFA enforcement. No identity provider is integrated, so this is reported as SKIP and never PASS.
Complete-CgStep @{ Outcome = 'skip'; Reason = 'MFA enforcement needs an identity provider integration, which this pack does not have; not validated [CSCRF-ID-07]' } 'id-07'
