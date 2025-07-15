import {SignedXml} from 'xml-crypto';
import {select} from 'xpath';
import {DOMParser} from '@xmldom/xmldom';
import xmlenc from 'xml-encryption';
import {getContext} from './api.js';
import utility from './utility.js';
import {flattenDeep} from "./utility.js";
import fs from 'node:fs'
import {SignatureVerifierOptions} from "./libsaml.js";
import libsaml from './libsaml.js'
import {algorithms, wording} from "./urn.js";

const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUse = wording.certUse;
const {dom} = getContext();
const urlParams = wording.urlParams;

interface VerifyAndDecryptResult {
    verified: boolean;
    soapXml?: string;
    decryptedAssertion?: string;
    artifactResolve?: any;
    artifactResponse?: any;
    response?: any;
    assertion?: any;
}

interface VerifyOptions {
    metadata?: any;
    privateKey?: string;
    privateKeyPass?: string;
    signatureAlgorithm?: string;
}

async function verifyAndDecryptSoapMessage(
    soapXml: string,
    opts: VerifyOptions
): Promise<any> {
    const {dom} = getContext();
    const doc = dom.parseFromString(soapXml, 'application/xml');
    const docParser = new DOMParser();

    // 为 SOAP 消息定义 XPath
    const artifactResolveXpath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResolve']";
    const artifactResponseXpath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResponse']";

    // 检测 ArtifactResolve 或 ArtifactResponse 的存在
    // @ts-expect-error
    const artifactResolveNodes = select(artifactResolveXpath, doc);
    // @ts-expect-error
    const artifactResponseNodes = select(artifactResponseXpath, doc);

    // 根据消息类型选择合适的 XPath
    let basePath = "";
    if (artifactResolveNodes.length > 0) {
        basePath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResolve']";
    } else if (artifactResponseNodes.length > 0) {
        basePath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResponse']";
    } else {
        throw new Error('ERR_UNSUPPORTED_SOAP_MESSAGE_TYPE');
    }

    // 基于 SOAP 结构重新定义 XPath
    const messageSignatureXpath = `${basePath}/*[local-name(.)='Signature']`;
    const assertionSignatureXpath = `${basePath}/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Signature']`;
    const wrappingElementsXPath = `${basePath}/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']`;
    const encryptedAssertionsXpath = `${basePath}/*[local-name(.)='Response']/*[local-name(.)='EncryptedAssertion']`;

    // 包装攻击检测
    // @ts-expect-error
    const wrappingElementNode = select(wrappingElementsXPath, doc);
    if (wrappingElementNode.length !== 0) {
        throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
    }

    // @ts-expect-error
    const encryptedAssertions = select(encryptedAssertionsXpath, doc);
    // @ts-expect-error
    const messageSignatureNode = select(messageSignatureXpath, doc);
    // @ts-expect-error
    const assertionSignatureNode = select(assertionSignatureXpath, doc);

    let selection: any[] = [];

    if (messageSignatureNode.length > 0) {
        selection = selection.concat(messageSignatureNode);
    }
    if (selection.length === 0) {
        throw new Error('ERR_ZERO_SIGNATURE');
    }
    console.log("开始5===============================")

    console.log("--------------------messageType----------------------")

    /** */
        // @ts-ignore
    let [verified, verifiedAssertionNode] = verifySignature(selection, doc, opts);
    /** 如果是artifactResolve 验证签名就够了*/
    if (verified && artifactResolveNodes.length > 0) {
        return [verified, verifiedAssertionNode]
    }


}

function verifySignature(selection, doc, opts: SignatureVerifierOptions) {


    const docParser = new DOMParser();
    for (const signatureNode of selection) {
        const sig = new SignedXml();
        let verified = false;
        sig.signatureAlgorithm = opts.signatureAlgorithm!;
        if (!opts.keyFile && !opts.metadata) {
            throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }

        if (opts.keyFile) {
            sig.publicCert = fs.readFileSync(opts.keyFile)
        }

        if (opts.metadata) {
            const certificateNode = select(".//*[local-name(.)='X509Certificate']", signatureNode) as any;
            // certificate in metadata
            let metadataCert: any = opts.metadata.getX509Certificate(certUse.signing);
            // flattens the nested array of Certificates from each KeyDescriptor
            if (Array.isArray(metadataCert)) {
                metadataCert = flattenDeep(metadataCert);
            } else if (typeof metadataCert === 'string') {
                metadataCert = [metadataCert];
            }
            // normalise the certificate string
            metadataCert = metadataCert.map(utility.normalizeCerString);

            // no certificate in node  response nor metadata
            if (certificateNode.length === 0 && metadataCert.length === 0) {
                throw new Error('NO_SELECTED_CERTIFICATE');
            }

            // certificate node in response
            if (certificateNode.length !== 0) {
                const x509CertificateData = certificateNode[0].firstChild.data;
                const x509Certificate = utility.normalizeCerString(x509CertificateData);
                if (
                    metadataCert.length >= 1 &&
                    !metadataCert.find(cert => cert.trim() === x509Certificate.trim())
                ) {
                    // keep this restriction for rolling certificate usage
                    // to make sure the response certificate is one of those specified in metadata
                    throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
                }

                sig.publicCert = libsaml.getKeyInfo(x509Certificate).getKey();

            } else {
                // Select first one from metadata
                sig.publicCert = libsaml.getKeyInfo(metadataCert[0]).getKey();

            }
        }
        console.log("验证饿了--------------------")
        sig.loadSignature(signatureNode);
        verified = sig.checkSignature(doc.toString());

        // immediately throw error when any one of the signature is failed to get verified
        if (!verified) {
            throw new Error('ERR_FAILED_TO_VERIFY_SIGNATURE');
        }

        // attempt is made to get the signed Reference as a string();
        // note, we don't have access to the actual signedReferences API unfortunately
        // mainly a sanity check here for SAML. (Although ours would still be secure, if multiple references are used)
        if (!(sig.getSignedReferences().length >= 1)) {
            throw new Error('NO_SIGNATURE_REFERENCES')
        }
        const signedVerifiedXML = sig.getSignedReferences()[0];
        const rootNode = docParser.parseFromString(signedVerifiedXML, 'application/xml').documentElement;
        // process the verified signature:
        // case 1, rootSignedDoc is a response:
        console.log(rootNode?.localName)
        console.log("9999999999999999999999999999999")
        if (rootNode?.localName === 'Response') {

            // try getting the Xml from the first assertion
            const EncryptedAssertions = select(
                "./*[local-name()='EncryptedAssertion']",
                // @ts-expect-error misssing Node properties are not needed
                rootNode
            );
            const assertions = select(
                "./*[local-name()='Assertion']",
                // @ts-expect-error misssing Node properties are not needed
                rootNode
            );
            /**第三个参数代表是否加密*/
            // now we can process the assertion as an assertion
            if (EncryptedAssertions.length === 1) {
                /** 已加密*/
                return [true, EncryptedAssertions[0].toString(), true, false];
            }

            if (assertions.length === 1) {

                return [true, assertions[0].toString(), false, false];
            }

        } else if (rootNode?.localName === 'ArtifactResolve') {
            return [true, rootNode.toString(), false, false];
        } else if (rootNode?.localName === 'Assertion') {
            return [true, rootNode.toString(), false, false];
        } else if (rootNode?.localName === 'EncryptedAssertion') {
            return [true, rootNode.toString(), true, false];
        } else {
            return [true, null, false, false]; // signature is valid. But there is no assertion node here. It could be metadata node, hence return null
        }
    }
}

export default {
    verifyAndDecryptSoapMessage
}
