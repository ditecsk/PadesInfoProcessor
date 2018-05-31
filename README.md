# PAdES Info Processor v1.0
PAdES Info Processor is based on iText and provides following functionality for processing of PAdES signature in other applications:
-	Providing information about PAdES signatures within PDF document:
	-	type and signature level
	-	certificate of the signer
	-	information about the document covered with the signature (whole document, or a part of it)
-	Information about time stamps (if applicable)
	-	time
	-	time stamp certificate
-	Information about the signer (acquired from the certificate)
	-	serial number
	-	validity
	-	mandate information (specific in Slovakia according the legislation)
Information about the signatures is provided as a structured XML and processed in other applications.