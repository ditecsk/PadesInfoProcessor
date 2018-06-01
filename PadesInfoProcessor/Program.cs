using iText.Signatures;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PadesInfoProcessor
{
    class Program
    {
        static void Main(string[] args)
        {
            MemoryStream ms = null;
            byte[] password = null;
            for (int i = 0; i < args.Length; i++)
            {
                string[] argArr = args[i].Split(new char[] { ':' }, StringSplitOptions.None);

                string prefix;
                string value = null;

                prefix = argArr[0];
                if(argArr.Length > 1)
                    value = argArr[1];

                switch (prefix.ToUpper())
                {
                    case "-N":
                    case "/N":
                        if (ms != null || value == null)
                            throw new Exception("incorrect input arguments");

                        if (File.Exists(value))
                            ms = new MemoryStream(File.ReadAllBytes(value));
                        break;
                    case "-D":
                    case "/D":
                        if (ms != null || value == null)
                            throw new Exception("incorrect input arguments");

                        if (File.Exists(value))
                            ms = new MemoryStream(Convert.FromBase64String(value));
                        break;
                    case "-P":
                    case "/P":
                        if (value == null)
                            throw new Exception("incorrect input arguments");

                        password = Encoding.ASCII.GetBytes(value);
                        break;
                    case "-HELP":
                    case "/HELP":
                    case "-?":
                    case "/?":
                        Console.Write("Retrieves PAdES signatures and returns informations structured into XML" + Environment.NewLine +
                                      "document." + Environment.NewLine +
                                      Environment.NewLine +
                            "PadesInfoProcessor [/N:[path][filename]] [/D:[filedata]] [/P:[password]]" + Environment.NewLine +
                            "  /N:[path][filename]" + Environment.NewLine +
                            "               Specifies PDF document file path to retrieve informations." + Environment.NewLine +
                            "  /D:[filedata]" + Environment.NewLine +
                            "               Specifies PDF document data encoded with Base64." + Environment.NewLine +
                            "  /P:[password]" + Environment.NewLine +
                            "               Specifies password if PDF document is encrypted." + Environment.NewLine +
                            Environment.NewLine);
                        break;
                    default:
                        break;
                }
            }
            

            string output = string.Empty;
            if (ms != null)
            {
                iText.Kernel.Pdf.PdfReader pdfReader;
                if(password == null)
                {
                    pdfReader = new iText.Kernel.Pdf.PdfReader(ms);
                }
                else
                {
                    pdfReader = new iText.Kernel.Pdf.PdfReader(ms, (new iText.Kernel.Pdf.ReaderProperties()).SetPassword(password));
                }
                
                SignatureUtil su = new SignatureUtil(new iText.Kernel.Pdf.PdfDocument(pdfReader));
                IList<string> sigNames = su.GetSignatureNames();
                output += "<PdfSignatures>";
                foreach (string sigName in sigNames)
                {
                    PdfSignature sig = su.GetSignature(sigName);

                    //string cert = sig.GetCert().GetValue();
                    string coversWholeDoc = su.SignatureCoversWholeDocument(sigName).ToString();
                    string signingTime = getDate(sig.GetDate());
                    string contentType = sig.GetSubFilter().ToString().Replace("/", "");
                    string reason = sig.GetReason();
                    string location = sig.GetLocation();

                    output += "<PdfSignature>";
                    output += "<SignatureName>" + sigName + "</SignatureName>";
                    output += "<PdfSigningTimeUtc>" + signingTime + "</PdfSigningTimeUtc>";
                    output += "<Reason>" + reason + "</Reason>";
                    output += "<Location>" + location + "</Location>";
                    output += "<CoversWholeDocument>" + coversWholeDoc + "</CoversWholeDocument>";
                    output += "<ContentType>" + contentType + "</ContentType>";
                    output += processByPdfPKCS7(sig.GetContents().GetValueBytes(), contentType);

                    output += "</PdfSignature>";
                }
                output += "</PdfSignatures>";
            }
            File.WriteAllText(@"D:\PadesInfoProcessorOutput.xml", output);
            Console.Write(output);
        }

        private static string getDate(iText.Kernel.Pdf.PdfString dateValue)
        {
            if (dateValue == null)
                return "";

            return DateTime.ParseExact(dateValue.GetValue().Substring(2).Replace('\'',':'), "yyyyMMddHHmmsszzz:", System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime().ToString("o");
        }

        private static string processByPdfPKCS7(byte[] contents, string subFilter)
        {
            string output = string.Empty;

            PdfPKCS7 pkcs7 = new PdfPKCS7(contents, new iText.Kernel.Pdf.PdfName(subFilter));
            //pkcs7.
            X509Certificate signingCert = pkcs7.GetSigningCertificate();
            DateTime signingTime = pkcs7.GetSignDate();
            TimeStampToken timeStampToken = pkcs7.GetTimeStampToken();
            output += "<SignerInfo>";
            //output += "<SignatureType>" + (signaturePolicyOid == null ? "PAdES_BES" : "PAdES_EPES") + "</SignatureType>";
            output += "<SigningCertificate>" + Convert.ToBase64String(signingCert.GetEncoded()) + "</SigningCertificate>";
            output += "<SigningTimeUtc>" + signingTime.ToUniversalTime().ToString("o") + "</SigningTimeUtc>";

            output += "<TimeStamps>";
            if (timeStampToken != null)
            {
                output += "<TimeStamp>";
                output += "<TimeStampDateTimeUtc>";
                output += DateTime.SpecifyKind(timeStampToken.TimeStampInfo.GenTime, DateTimeKind.Utc).ToUniversalTime().ToString("o");
                output += "</TimeStampDateTimeUtc>";
                output += "<TimeStampSigningCertificate>";
                output += Convert.ToBase64String(getTimeStampCert(timeStampToken).GetEncoded());
                output += "</TimeStampSigningCertificate>";
                output += "</TimeStamp>";
            }
            output += "</TimeStamps>";
            output += "</SignerInfo>";

            return output;
        }

        //private static string processSignedData(byte[] cadesData)
        //{
            

        //    string output = string.Empty;
        //    Utils.Cades.CAdESParser cades = new Utils.Cades.CAdESParser(cadesData);
        //    if (!cades.IsInitialized())
        //    {
        //        Console.Error.Write("PadesInfoProcessor.processSignedData: Nepodarilo sa inicializovat CAdESParser. Detail: " + cades.ErrorMessage);
        //        return null;
        //    }



        //    long signerInfoCount = cades.GetSignerInfoCount();

        //    for (int n = 0; n < signerInfoCount; n++)
        //    {
        //        output += "<SignerInfo>";
        //        try
        //        {
        //            //XmlDocument xSignatureDoc = DocUtility.CreateXmlDocument(xSignatureNode.OuterXml);

        //            //get xades type
        //            Utils.Cades.CAdESParser.CadesZepType zt = cades.GetSignatureType(n);
        //            Utils.Cades.CAdESParser.CadesBaselineProfileConfLevel confLevel = cades.GetSignatureConformanceLevel(n);
        //            if (zt == Utils.Cades.CAdESParser.CadesZepType.Unknown)
        //            {
        //                throw new Exception("Unknown CAdES type found.");
        //            }
                    
        //            //get signing certificate subjects CN
        //            byte[] sigCertData = cades.GetSigningCertificate(n);

        //            //X509Certificate signingCert = new X509CertificateParser().ReadCertificate(sigCertData);
        //            //string signingCertInfo = this.getSigningCertInfo(signingCert);
                    

        //            //create cades node
        //            int version;
        //            string hashAlgorithmOid;
        //            string signatureAlgOid;
        //            DateTime? signingTime;
        //            string messageDigestB64;
        //            string signaturePolicyOid;
        //            string sigPolicyHashAlgorithm;
        //            string sigPolicyHashValue;
        //            string contentType;
        //            string signatureValueB64;
        //            cades.GetSignerInfoParameters(n, out version, out hashAlgorithmOid, out signatureAlgOid, out signingTime, out messageDigestB64, out signaturePolicyOid, out sigPolicyHashAlgorithm, out sigPolicyHashValue, out contentType, out signatureValueB64);

        //            output += "<SignatureType>" + (signaturePolicyOid == null ? "PAdES_BES" : "PAdES_EPES") + "</SignatureType>";
        //            output += "<SigningCertificate>" + Convert.ToBase64String(sigCertData) + "</SigningCertificate>";
        //            output += "<SigningTime>" + (signingTime.HasValue ? signingTime.Value.ToUniversalTime().ToString("o") : "") + "</SigningTime>";

        //            output += "<TimeStamps>";
        //            List<object> timeStamps = new List<object>();
        //            if (zt >= Utils.Cades.CAdESParser.CadesZepType.CAdES_T)
        //            {

        //                //add timestamp info for T							
        //                int sigTimeStampCount = cades.GetSignatureTimeStampCount(n);
        //                for (long ts = 0; ts < sigTimeStampCount; ts++)
        //                {
        //                    TimeStampToken timeStampToken = new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(cades.GetSignatureTimeStampToken(ts, n)));
        //                    output += "<TimeStamp>";
        //                    output += "<TimeStampDateTimeUtc>";
        //                    output += DateTime.SpecifyKind(timeStampToken.TimeStampInfo.GenTime, DateTimeKind.Utc).ToUniversalTime().ToString();
        //                    output += "</TimeStampDateTimeUtc>";
        //                    output += "<TimeStampSignatureCertificate>";
        //                    output += Convert.ToBase64String(getTimeStampCert(timeStampToken).GetEncoded());
        //                    output += "</TimeStampSignatureCertificate>";
        //                    output += "</TimeStamp>";
        //                }
        //            }
        //            output += "</TimeStamps>";

        //            //this.authorizations.Add(new Authorization(authObjs, null, signingTime.HasValue ? signingTime.Value : DateTime.MinValue, "CAdES", zt.ToString(), signingCert), zt >= CAdESParser.CadesZepType.CAdES_T, timeStamps));
        //        }
        //        catch (Exception ex)
        //        {
        //            Console.Error.Write("AuthorizationInfo.processSignedData: Nastala chyba pocas spracovania CAdES podpisu. Detail: " + ex.ToString());
        //            return null;
        //        }

        //        output += "</SignerInfo>";
        //    }

        //    return output;
        //}

        private static X509Certificate getTimeStampCert(TimeStampToken tsToken)
        {
            X509Certificate signerCert = null;

            if (tsToken != null)
            {
                Org.BouncyCastle.X509.Store.IX509Store x509Certs = tsToken.GetCertificates("Collection");

                System.Collections.ArrayList certs = new System.Collections.ArrayList(x509Certs.GetMatches(null));

                // nájdenie podpisového certifikátu tokenu v kolekcii
                foreach (X509Certificate cert in certs)
                {
                    // kontrola issuer name a seriového čísla
                    if (cert.IssuerDN.Equivalent(tsToken.SignerID.Issuer) &&
                        cert.SerialNumber.Equals(tsToken.SignerID.SerialNumber))
                    {
                        signerCert = cert;
                        break;
                    }
                }
            }

            return signerCert;
        }
    }
}
