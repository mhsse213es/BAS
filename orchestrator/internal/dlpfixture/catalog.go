package dlpfixture

import "fmt"

// scenarioID constants name every real scenario this catalog references,
// matching scenarios/dlp-exfiltration-*.yaml's own id: fields exactly.
const (
	scenarioValidation   = "dlp-exfiltration-validation"
	scenarioSinkHTTPS    = "dlp-exfiltration-sink-https"
	scenarioDNSTunnel    = "dlp-exfiltration-dns-tunnel"
	scenarioSFTP         = "dlp-exfiltration-sftp"
	scenarioSMTP         = "dlp-exfiltration-smtp"
	scenarioCloudStorage = "dlp-exfiltration-cloud-storage"
	scenarioWebhook      = "dlp-exfiltration-webhook"
	scenarioCodeRepo     = "dlp-exfiltration-coderepo"
	scenarioTelnet       = "dlp-exfiltration-telnet"
	scenarioMultichannel = "dlp-exfiltration-multichannel"
	scenarioDevtools     = "dlp-exfiltration-devtools"
	scenarioAIPrompt     = "dlp-exfiltration-ai-prompt"
	scenarioDBExport     = "dlp-exfiltration-db-export"
	scenarioEmailRecipients = "dlp-exfiltration-email-recipients"
)

// AllFixtures returns Audspect's real, current seed catalog of every
// synthetic data fixture value embedded in scenarios/dlp-exfiltration-*.yaml
// today (DLP Mastery Phase 1 priority 2). Every Value and Occurrence was
// confirmed by direct inspection of the real YAML files, not inferred
// from a scenario's own description text -- the exact mistake that
// caused dlpprofile's final-review Critical finding. The companion
// drift test (drift_test.go) re-verifies this catalog against the live
// files on every test run.
func AllFixtures() ([]Fixture, error) {
	var fixtures []Fixture
	add := func(f Fixture, err error) error {
		if err != nil {
			return err
		}
		fixtures = append(fixtures, f)
		return nil
	}

	// The BFSI/India anchor record: the single most duplicated fixture
	// in the whole corpus, byte-for-byte identical across every base
	// "Traffic Simulation"/"Exfiltration" step in all 10 scenario files.
	if err := add(NewFixture("bfsi-india-anchor",
		"BFSI/India customer record (PAN/Aadhaar/SWIFT/UPI/credit-card CSV)",
		[]string{"CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard", "ABCDE1234F", "123456789012", "SBININBBXXX", "fake.user@upi", "4111111111111111"},
		[]Occurrence{
			{scenarioValidation, "DLP Validation — USB Exfiltration of Regulated Data (T1052.001)"},
			{scenarioValidation, "DLP Validation — Clipboard Exposure of Regulated Data (T1115)"},
			{scenarioValidation, "DLP Validation — Print Exfiltration of Regulated Data (T1052)"},
			{scenarioValidation, "DLP Validation — Archive Staging of Regulated Data (T1560.001)"},
			{scenarioValidation, "DLP Validation — Local Staging of Regulated Data to a Shared Path (T1074.001)"},
			{scenarioMultichannel, "DLP Validation — USB Exfiltration of Regulated Data (T1052.001)"},
			{scenarioMultichannel, "DLP Validation — Clipboard Exposure of Regulated Data (T1115)"},
			{scenarioMultichannel, "DLP Validation — Print Exfiltration of Regulated Data (T1052)"},
			{scenarioMultichannel, "DLP Validation — Archive Staging of Regulated Data (T1560.001)"},
			{scenarioMultichannel, "DLP Validation — Local Staging of Regulated Data to a Shared Path (T1074.001)"},
			{scenarioMultichannel, "DLP Validation — Sink-Verified HTTPS Exfiltration (T1567)"},
			{scenarioMultichannel, "DLP Validation — DNS Tunneling Exfiltration (T1071.004)"},
			{scenarioMultichannel, "DLP Validation — SFTP Exfiltration (T1048.002)"},
			{scenarioMultichannel, "DLP Validation — SMTP Exfiltration (T1048.003)"},
			{scenarioSinkHTTPS, "DLP Validation — Sink-Verified HTTPS Exfiltration (T1567)"},
			{scenarioDNSTunnel, "DLP Validation — DNS Tunneling Exfiltration (T1071.004)"},
			{scenarioSFTP, "DLP Validation — SFTP Exfiltration (T1048.002)"},
			{scenarioSMTP, "DLP Validation — SMTP Exfiltration (T1048.003)"},
			{scenarioCloudStorage, "DLP Validation — S3-Compatible Traffic Simulation (T1567.002)"},
			{scenarioCloudStorage, "DLP Validation — Azure Blob-Compatible Traffic Simulation (T1567.002)"},
			{scenarioCloudStorage, "DLP Validation — OneDrive (Graph API)-Compatible Traffic Simulation (T1567.002)"},
			{scenarioCloudStorage, "DLP Validation — Google Drive-Compatible Traffic Simulation (T1567.002)"},
			{scenarioCloudStorage, "DLP Validation — Dropbox-Compatible Traffic Simulation (T1567.002)"},
			{scenarioCloudStorage, "DLP Validation — Google Cloud Storage-Compatible Traffic Simulation (T1567.002)"},
			{scenarioCloudStorage, "DLP Validation — Box-Compatible Traffic Simulation (T1567.002)"},
			{scenarioWebhook, "DLP Validation — Slack-Compatible Webhook Traffic Simulation (T1567.004)"},
			{scenarioWebhook, "DLP Validation — Microsoft Teams-Compatible Webhook Traffic Simulation (T1567.004)"},
			{scenarioCodeRepo, "DLP Validation — GitHub Gist-Compatible Traffic Simulation (T1567.001)"},
			{scenarioCodeRepo, "DLP Validation — GitLab Snippet-Compatible Traffic Simulation (T1567.001)"},
			{scenarioTelnet, "DLP Validation — Telnet-Compatible Login Session Simulation (T1048.003)"},
		},
		"the one fixture every other DLP scenario in this program shares; centralizing it here is this package's primary duplication-elimination target")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("aws-credential-pair",
		"AWS access-key/secret-key pair",
		[]string{"aws_access_key_id=AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		[]Occurrence{
			{scenarioCloudStorage, "DLP Validation — S3-Compatible Exfiltration of AWS Cloud Credentials (T1567.002)"},
			{scenarioWebhook, "DLP Validation — Slack-Compatible Exfiltration of AWS Cloud Credentials (T1567.004)"},
			{scenarioTelnet, "DLP Validation — Telnet Exfiltration of AWS Cloud Credentials (T1048.003)"},
			{scenarioSinkHTTPS, "DLP Validation — HTTPS Exfiltration of AWS Cloud Credentials (T1567)"},
		},
		"second-most-duplicated fixture; the secret half is also reused bare in the Python Source Code step (see aws-secret-key-reuse)")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("aws-secret-key-reuse",
		"AWS secret key (bare, no access-key-id pairing)",
		[]string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		[]Occurrence{{scenarioSinkHTTPS, "DLP Validation — HTTPS Exfiltration of Python Source Code (T1567)"}},
		"the Python Source Code step reuses aws-credential-pair's own secret value, bare, as its embedded fake secret -- a real, separate duplication, not a copy-paste error in this catalog")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("oracle-connection-string",
		"Oracle DB connection string",
		[]string{"Data Source=BAS-SIM-ORACLE", "BAS-SIM-DLP-Placeholder1"},
		[]Occurrence{
			{scenarioSinkHTTPS, "DLP Validation — HTTPS Exfiltration of Oracle DB Connection String (T1567)"},
			{scenarioTelnet, "DLP Validation — Telnet Exfiltration of Oracle DB Connection String (T1048.003)"},
		},
		"duplicated identically across its two citing steps")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("mssql-connection-string", "MS SQL Server connection string",
		[]string{"Server=bas-sim-mssql", "BAS-SIM-DLP-Placeholder2"},
		[]Occurrence{{scenarioSFTP, "DLP Validation — SFTP Exfiltration of MS SQL Connection String (T1048.002)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("mongodb-connection-string", "MongoDB connection string",
		[]string{"mongodb://bas_sim_user", "BAS-SIM-DLP-Placeholder3"},
		[]Occurrence{{scenarioCloudStorage, "DLP Validation — Azure Blob-Compatible Exfiltration of MongoDB Connection String (T1567.002)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("postgresql-connection-string", "PostgreSQL connection string",
		[]string{"postgresql://bas_sim_user", "BAS-SIM-DLP-Placeholder4"},
		[]Occurrence{{scenarioWebhook, "DLP Validation — Slack-Compatible Exfiltration of PostgreSQL Connection String (T1567.004)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("db2-connection-string", "DB2 connection string",
		[]string{"DATABASE=BASSIMDLP", "BAS-SIM-DLP-Placeholder5"},
		[]Occurrence{{scenarioCodeRepo, "DLP Validation — GitLab Snippet-Compatible Exfiltration of DB2 Connection String (T1567.001)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("java-source-code", "Java source code with embedded fake secret",
		[]string{"BAS-SIM-DLP-Placeholder6"},
		[]Occurrence{{scenarioSFTP, "DLP Validation — SFTP Exfiltration of Java Source Code (T1048.002)"}},
		"placeholder token only -- the surrounding Java syntax is not reproduced here to avoid PowerShell backtick-escaping drift")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("csharp-source-code", "C# source code with embedded fake secret",
		[]string{"BAS-SIM-DLP-Placeholder7"},
		[]Occurrence{{scenarioCloudStorage, "DLP Validation — Google Drive-Compatible Exfiltration of C# Source Code (T1567.002)"}},
		"placeholder token only -- the surrounding C# syntax is not reproduced here to avoid PowerShell backtick-escaping drift")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("go-source-code", "Go source code with embedded fake secret",
		[]string{"BAS-SIM-DLP-Placeholder8"},
		[]Occurrence{{scenarioSMTP, "DLP Validation — SMTP Exfiltration of Go Source Code (T1048.003)"}},
		"placeholder token only -- the surrounding Go syntax is not reproduced here to avoid PowerShell backtick-escaping drift")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("php-source-code", "PHP source code with embedded fake secret",
		[]string{"BAS-SIM-DLP-Placeholder9"},
		[]Occurrence{{scenarioCodeRepo, "DLP Validation — GitHub Gist-Compatible Exfiltration of PHP Source Code (T1567.001)"}},
		"placeholder token only -- the surrounding PHP syntax is not reproduced here to avoid PowerShell backtick-escaping drift")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("perl-source-code", "Perl source code with embedded fake secret",
		[]string{"BAS-SIM-DLP-Placeholder10"},
		[]Occurrence{{scenarioCodeRepo, "DLP Validation — GitHub Gist-Compatible Exfiltration of Perl Source Code (T1567.001)"}},
		"placeholder token only -- the surrounding Perl syntax is not reproduced here to avoid PowerShell backtick-escaping drift")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("gcp-service-account-json", "GCP service-account JSON credential",
		[]string{"bas-sim-dlp-project", "bas-sim@bas-sim-dlp-project.iam.gserviceaccount.com"},
		[]Occurrence{{scenarioSMTP, "DLP Validation — SMTP Exfiltration of GCP Cloud Credentials (T1048.003)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("azure-service-principal-json", "Azure service-principal JSON credential",
		[]string{"BAS-SIM-DLP-ServicePrincipal", "00000000-1111-0000-0000-000000000000"},
		[]Occurrence{
			{scenarioDNSTunnel, "DLP Validation — DNS Tunneling of Azure Cloud Credentials (T1071.004)"},
			{scenarioCodeRepo, "DLP Validation — GitLab Snippet-Compatible Exfiltration of Azure Cloud Credentials (T1567.001)"},
		},
		"duplicated identically across its two citing steps")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("financial-statement", "Synthetic financial statement",
		[]string{"Financial Statement (Synthetic)", "BAS-SIM-Corp"},
		[]Occurrence{{scenarioSFTP, "DLP Validation — SFTP Exfiltration of Financial Statement (T1048.002)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("israeli-id-record", "Israeli national ID record",
		[]string{"Name,ID", "John BasSim,000000000"},
		[]Occurrence{{scenarioSFTP, "DLP Validation — SFTP Exfiltration of Israeli ID Record (T1048.002)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("amex-card-record", "American Express card record",
		[]string{"American Express,378282246310005"},
		[]Occurrence{{scenarioSFTP, "DLP Validation — SFTP Exfiltration of American Express Card Record (T1048.002)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("uk-nino-record", "UK National Insurance Number record",
		[]string{"Name,NINO", "John BasSim,QQ123456C"},
		[]Occurrence{{scenarioDNSTunnel, "DLP Validation — DNS Tunneling of UK National Insurance Number (T1071.004)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("mastercard-card-record", "Mastercard card record",
		[]string{"Mastercard,5555555555554444"},
		[]Occurrence{{scenarioDNSTunnel, "DLP Validation — DNS Tunneling of Mastercard Card Record (T1071.004)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("medical-record", "Patient/MRN/Diagnosis medical record",
		[]string{"Patient,MRN,Diagnosis", "Synthetic-Test-Diagnosis"},
		[]Occurrence{{scenarioSMTP, "DLP Validation — SMTP Exfiltration of Medical Record (T1048.003)"}},
		"the only real healthcare-shaped payload in the corpus -- see dlpprofile's DLPPROFILE-HEALTHCARE Covered entry, which cites exactly this occurrence")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("discover-card-record", "Discover card record",
		[]string{"Discover,6011111111111117"},
		[]Occurrence{
			{scenarioSMTP, "DLP Validation — SMTP Exfiltration of Discover Card Record (T1048.003)"},
			{scenarioTelnet, "DLP Validation — Telnet Exfiltration of Discover Card Record (T1048.003)"},
		},
		"duplicated identically across its two citing steps")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("employment-contract", "Synthetic employment contract",
		[]string{"Employment Contract (Synthetic)", "BAS-SIM-Employee"},
		[]Occurrence{{scenarioSMTP, "DLP Validation — SMTP Exfiltration of Employment Contract (T1048.003)"}},
		"cited by dlpprofile's DLPPROFILE-GOVERNMENT Covered entry alongside partnership-agreement")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("partnership-agreement", "Synthetic partnership agreement",
		[]string{"Partnership Agreement (Synthetic)", "BAS-SIM-Corp-A"},
		[]Occurrence{{scenarioCloudStorage, "DLP Validation — OneDrive (Graph API)-Compatible Exfiltration of Partnership Agreement (T1567.002)"}},
		"cited by dlpprofile's DLPPROFILE-GOVERNMENT Covered entry alongside employment-contract")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("us-ssn-record", "US Social Security Number record",
		[]string{"Name,SSN", "000-12-3456"},
		[]Occurrence{{scenarioSinkHTTPS, "DLP Validation — HTTPS Exfiltration of US SSN Record (T1567)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("visa-card-record", "Visa card record",
		[]string{"Visa,4111111111111111"},
		[]Occurrence{{scenarioSinkHTTPS, "DLP Validation — HTTPS Exfiltration of Visa Card Record (T1567)"}},
		"its card number literally matches bfsi-india-anchor's CreditCard field -- a separate, deliberate duplication in the real files, not a catalog error")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("maestro-card-record", "Maestro card record",
		[]string{"Maestro,6759649826438453"},
		[]Occurrence{{scenarioWebhook, "DLP Validation — Microsoft Teams-Compatible Exfiltration of Maestro Card Record (T1567.004)"}},
		"single occurrence, no duplication to eliminate, catalogued for drift protection")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("devtools-artifacts-and-credentials", "Synthetic developer-tooling artifact, package and document payloads",
		[]string{"[BAS-SIM-DEV]", "AKIAIOSFODNN7EXAMPLE", "BAS-SIM-DEV-PRIVATE-KEY-PLACEHOLDER"},
		[]Occurrence{
			{scenarioDevtools, "DLP Validation — CI/CD Build Artifact Upload via HTTPS Sink (T1567)"},
			{scenarioDevtools, "DLP Validation — Package Publish With Embedded Credential via HTTPS Sink (T1567)"},
			{scenarioDevtools, "DLP Validation — Internal Design Document Shared Via Developer Tooling (T1567)"},
		},
		"three developer-tooling steps share one synthetic payload header; AWS example key and placeholder only")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("ai-prompt-multitype-record", "Synthetic multi-type record pasted into a chat or connector prompt",
		[]string{"[BAS-SIM-DLP]", "ABCDE1234F", "123456789012", "SBININBBXXX", "fake.user@upi", "4111111111111111"},
		[]Occurrence{
			{scenarioAIPrompt, "DLP Validation — AI Chat-Completion Exfiltration of Multi-Type Sensitive Record (T1567)"},
			{scenarioAIPrompt, "DLP Validation — AI Connector-Ingestion Exfiltration of Multi-Type Sensitive Record (T1567)"},
		},
		"same synthetic record as the BFSI anchor, carried in an AI prompt")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}
	if err := add(NewFixture("ai-prompt-go-source", "Synthetic Go source snippet with a placeholder password",
		[]string{"[BAS-SIM-DLP]", "BAS-SIM-DLP-Placeholder8"},
		[]Occurrence{{scenarioAIPrompt, "DLP Validation — AI Chat-Completion Exfiltration of Go Source Code (T1567)"}},
		"placeholder credential only, no real secret")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}
	if err := add(NewFixture("ai-prompt-employment-contract", "Synthetic employment contract text sent to an AI connector",
		[]string{"[BAS-SIM-DLP] Employment Contract (Synthetic)", "BAS-SIM-Employee"},
		[]Occurrence{{scenarioAIPrompt, "DLP Validation — AI Connector-Ingestion Exfiltration of Employment Contract (T1567)"}},
		"synthetic contract, salary shown as a zero placeholder")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}
	if err := add(NewFixture("db-export-multitype-extracts", "Synthetic multi-type extract from SQL, BI, CRM and warehouse exports",
		[]string{"[BAS-SIM-DLP]", "ABCDE1234F", "123456789012", "SBININBBXXX", "fake.user@upi"},
		[]Occurrence{
			{scenarioDBExport, "DLP Validation — SQL Query Result Export via SFTP Managed File Transfer (T1048.002)"},
			{scenarioDBExport, "DLP Validation — BI Dashboard Export via S3-Compatible Cloud Upload (T1567.002)"},
			{scenarioDBExport, "DLP Validation — CRM/ERP Report Export via OneDrive-Compatible Upload (T1567.002)"},
			{scenarioDBExport, "DLP Validation — Data Warehouse Extract Export via Slack-Compatible Webhook (T1567.004)"},
		},
		"four export channels carry the same synthetic record shape")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := add(NewFixture("email-recipient-multitype-record", "Synthetic multi-type record sent to external and personal mail recipients",
		[]string{"[BAS-SIM-DLP]", "ABCDE1234F", "123456789012", "SBININBBXXX", "fake.user@upi", "4111111111111111"},
		[]Occurrence{
			{scenarioEmailRecipients, "DLP Validation — SMTP Exfiltration to External Business Recipient (T1048.003)"},
			{scenarioEmailRecipients, "DLP Validation — SMTP Exfiltration to Personal Mail Address (T1048.003)"},
		},
		"same synthetic record as the BFSI anchor, sent to reserved example domains only")); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}

	if err := ValidateCatalog(fixtures); err != nil {
		return nil, fmt.Errorf("loading seed fixture catalog: %w", err)
	}
	return fixtures, nil
}
