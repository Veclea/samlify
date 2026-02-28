import {base64Decode} from './utility.js';
import {verifyTime} from './validator.js';
import libsaml from './libsaml.js';
import * as uuid from 'uuid'
import {select} from 'xpath';
import {DOMParser} from '@xmldom/xmldom';
import {sendArtifactResolve} from "./soap.js";
import {
    extract,
    type  ExtractorFields,
    loginRequestFields,
    loginResponseFields,
    loginResponseStatusFields,
    loginArtifactResponseStatusFields,
    logoutRequestFields,
    logoutResponseFields,
    logoutResponseStatusFields
} from './extractor.js';

import {BindingNamespace, ParserType, StatusCode, wording} from './urn.js';


const bindDict = wording.binding;
const urlParams = wording.urlParams;

export interface FlowResult {
    samlContent: string;
    extract: any;
    sigAlg?: string | null;
}

// get the default extractor fields based on the parserType
function getDefaultExtractorFields(parserType: ParserType, assertion?: any): ExtractorFields {
    switch (parserType) {
        case ParserType.SAMLRequest:
            return loginRequestFields;
        case ParserType.SAMLResponse:
            if (!assertion) {
                // unexpected hit
                throw new Error('ERR_EMPTY_ASSERTION');
            }
            return loginResponseFields(assertion);
        case ParserType.LogoutRequest:
            return logoutRequestFields;
        case ParserType.LogoutResponse:
            return logoutResponseFields;
        default:
            throw new Error('ERR_UNDEFINED_PARSERTYPE');
    }
}

// proceed the redirect binding flow
async function redirectFlow(options): Promise<FlowResult> {

    const {request, parserType, self, checkSignature = true, from} = options;
    const {query, octetString} = request;
    const {SigAlg: sigAlg, Signature: signature} = query;

    const targetEntityMetadata = from.entityMeta;

    // ?SAMLRequest= or ?SAMLResponse=
    const direction = libsaml.getQueryParamByType(parserType);
    const content = query[direction];

    // query must contain the saml content
    if (content === undefined) {
        return Promise.reject('ERR_REDIRECT_FLOW_BAD_ARGS');
    }

    /*  const xmlString = inflateString(decodeURIComponent(content));*/
    // @ts-ignore
    let {xml: xmlString} = libsaml.validateAndInflateSamlResponse(content);
    // validate the xml
    try {
        let result = await libsaml.isValidXml(xmlString);
    } catch (e) {
        return Promise.reject('ERR_INVALID_XML');
    }

    // check status based on different scenarios
    await checkStatus(xmlString, parserType);

    let assertion: string = '';

    if (parserType === urlParams.samlResponse) {
        // Extract assertion shortcut
        const verifiedDoc = extract(xmlString, [{
            key: 'assertion',
            localPath: ['~Response', 'Assertion'],
            attributes: [],
            context: true
        }]);
        if (verifiedDoc && verifiedDoc.assertion) {
            assertion = verifiedDoc.assertion as string;
        }
    }

    const extractorFields = getDefaultExtractorFields(parserType, assertion.length > 0 ? assertion : null);

    const parseResult: { samlContent: string, extract: any, sigAlg: (string | null) } = {
        samlContent: xmlString,
        sigAlg: null,
        extract: extract(xmlString, extractorFields),
    };

    // see if signature check is required
    // only verify message signature is enough
    if (checkSignature) {
        if (!signature || !sigAlg) {
            return Promise.reject('ERR_MISSING_SIG_ALG');
        }

        // put the below two assignments into verifyMessageSignature function
        const base64Signature = Buffer.from(decodeURIComponent(signature), 'base64');
        const decodeSigAlg = decodeURIComponent(sigAlg);

        const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

        if (!verified) {
            // Fail to verify message signature
            return Promise.reject('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION');
        }

        parseResult.sigAlg = decodeSigAlg;
    }

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const issuer = targetEntityMetadata.getEntityID();
    const extractedProperties = parseResult.extract;

    // unmatched issuer
    if (
        (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
        && extractedProperties
        && extractedProperties.issuer !== issuer
    ) {
        return Promise.reject('ERR_UNMATCH_ISSUER');
    }

    // invalid session time
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_EXPIRED_SESSION');
    }

    // invalid time
    // 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.conditions
        && !verifyTime(
            extractedProperties.conditions.notBefore,
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_CONDITION_UNCONFIRMED');
    }

    if (parserType === 'SAMLResponse') {
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
    }


    return Promise.resolve(parseResult);
}

// proceed the post flow
async function postFlow(options): Promise<FlowResult> {


    const {
        request,
        from,
        self,
        parserType,
        checkSignature = true
    } = options;
    const {body} = request;
    const direction = libsaml.getQueryParamByType(parserType);
    let encodedRequest = '';

    let samlContent = '';

    encodedRequest = body[direction];
    // @ts-ignore
    samlContent = String(base64Decode(encodedRequest))

    /** 增加判断是不是Soap 工件绑定*/

    const verificationOptions = {
        metadata: from.entityMeta,
        signatureAlgorithm: from.entitySetting.requestSignatureAlgorithm,
    };
    /** 断言是否加密应根据响应里面的字段判断*/
    let decryptRequired = from.entitySetting.isAssertionEncrypted;
    let extractorFields: ExtractorFields = [];
    // validate the xml first

    let res = await libsaml.isValidXml(samlContent).catch((error) => {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    });

    if (res !== true) {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    }
    if (parserType !== urlParams.samlResponse) {
        extractorFields = getDefaultExtractorFields(parserType, null);
    }
    // check status based on different scenarios
    await checkStatus(samlContent, parserType);
    /**检查签名顺序 */


    // 改进的postFlow函数中关于签名验证的部分
    const verificationResult = await libsaml.verifySignature(samlContent, verificationOptions,self);
    let resultObject = {
        isMessageSigned:true,//是否有外层的消息签名（Response或者Request 等最外层的签名）
        MessageSignatureStatus:true,//外层的签名是否经过验证
        isAssertionSigned:true,//是否有断言的签名
        AssertionSignatureStatus:true,//断言签名是否经过验证
        encrypted:true ,//断言是否加密
        decrypted:true ,//断言加密后断言是否解密成功，
        status:true,//是否全部通过验证,
        samlContent:'xxx',//xxx是通过验证后 解密后的整个响应，
        assertionContent:'xxx',//xxx是通过验证后 解密后的整个响应中的assertion 断言部分字符串,
        signMethod:"",//xxx是通过验证后 解密后的整个响应中的assertion 断言部分字符串,
    }
// 检查验证结果

    if (!verificationResult.status) {
        // 如果验证失败，根据具体情况返回错误
        /** 需要判断是不是  */
        if (verificationResult.isMessageSigned && !verificationResult.MessageSignatureStatus) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_MESSAGE_SIGNATURE');
        }
        if (verificationResult.isAssertionSigned && !verificationResult.AssertionSignatureStatus) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_ASSERTION_SIGNATURE');
        }
        if (verificationResult.encrypted && !verificationResult.decrypted) {
            return Promise.reject('ERR_FAIL_TO_DECRYPT_ASSERTION');
        }
        if (!verificationResult.isMessageSigned && verificationResult.type ==='LogoutRequest') {
            return Promise.reject('ERR_LogoutRequest_Need_Signature');
        }
        if (!verificationResult.isMessageSigned && verificationResult.type ==='LogoutResponse') {
            return Promise.reject('ERR_LogoutResponse_Need_Signature');
        }

        // 通用验证失败
        return Promise.reject('ERR_FAIL_TO_VERIFY_SIGNATURE_OR_DECRYPTION');
    }

// 更新samlContent为验证后的版本（可能已解密）
    samlContent = verificationResult.samlContent;

// 根据验证结果设置extractorFields
    if (verificationResult.assertionContent) {
        extractorFields = getDefaultExtractorFields(parserType, verificationResult.assertionContent);
    } else {
        // 如果没有断言内容（例如注销请求/响应），使用适当的处理方式
        extractorFields = getDefaultExtractorFields(parserType, null);
    }

    const parseResult = {
        samlContent: samlContent,
        extract: extract(samlContent, extractorFields),
    };

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const targetEntityMetadata = from.entityMeta;
    const issuer = targetEntityMetadata.getEntityID();
    const extractedProperties = parseResult.extract;
// unmatched issuer
    if (
        (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
        && extractedProperties
        && extractedProperties.issuer !== issuer
    ) {
        return Promise.reject('ERR_UNMATCH_ISSUER');
    }

// invalid session time
// only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_EXPIRED_SESSION');
    }

// invalid time
// 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.conditions
        && !verifyTime(
            extractedProperties.conditions.notBefore,
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_CONDITION_SESSION');
    }

    // invalid subjectConfirmation time
// invalid time
// 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.subjectConfirmation
        && !verifyTime(
            undefined,
            extractedProperties.subjectConfirmation.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_SUBJECT_UNCONFIRMED');
    }


//valid destination
//There is no validation of the response here. The upper-layer application
// should verify the result by itself to see if the destination is equal to the SP acs and
// whether the response.id is used to prevent replay attacks.
    console.log(extractedProperties)
    console.log("牛逼属性")
/*        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
        if (parserType === 'SAMLResponse') {
            let destination = extractedProperties?.response?.destination
            let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
                return item?.Location === destination
            })
            if (isExit?.length === 0) {
                return Promise.reject('ERR_Destination_URL');
            }
        }*/

// ============================
// VALIDATE Destination & Recipient
// ============================

    const { type } = verificationResult;
    const { response, subjectConfirmation } = extractedProperties || {};

// 获取 SP 配置的所有合法 ACS URLs（用于比对）
    const validACSUrls = (self.entitySetting?.assertionConsumerService || [])
        .map((item: any) => item.Location)
        .filter(Boolean);

    /**
     * Helper: Check if a given URL is in the list of valid ACS endpoints
     */
    function isValidACSEndpoint(url: string | undefined): boolean {
        return url != null && validACSUrls.includes(url);
    }

// 根据消息类型执行不同的验证
    switch (type) {
        case 'Response': // SAML Response (Login)
        {
            // 1. 验证协议层 Destination（必须匹配 ACS）
            const destination = response?.destination;
            if (!isValidACSEndpoint(destination)) {
                return Promise.reject('ERR_INVALID_DESTINATION');
            }

            // 2. 验证断言层 Recipient（必须匹配 ACS，且通常应等于 Destination）
            const recipient = subjectConfirmation?.recipient;
            if (!isValidACSEndpoint(recipient)) {
                return Promise.reject('ERR_INVALID_RECIPIENT');
            }

            // 可选：强制 Destination === Recipient（推荐）
            if (destination !== recipient) {
                // 注意：某些 IdP 可能不严格一致，但安全起见建议开启
                 return Promise.reject('ERR_DESTINATION_RECIPIENT_MISMATCH');
            }
        }
            break;

        case 'LogoutRequest': // IdP 发起的单点登出
        {
            // LogoutRequest 是 IdP → SP，SP 是接收方
            // 必须验证 Destination 是否为 SP 的 SLO endpoint（Single Logout Service）
            const destination = response?.destination; // 注意：LogoutRequest 的 root 元素是 <samlp:LogoutRequest>
            const validSLOUrls = (self.entitySetting?.singleLogoutService || [])
                .map((item: any) => item.Location)
                .filter(Boolean);

            if (destination && !validSLOUrls.includes(destination)) {
                return Promise.reject('ERR_INVALID_LOGOUT_DESTINATION');
            }

            // LogoutRequest 通常**不包含 Assertion**，所以无 Recipient
            // 如果有嵌套断言（罕见），可额外处理，但一般不需要
        }
            break;

        case 'LogoutResponse': // SP → IdP 的登出响应
        {
            // LogoutResponse 是 SP → IdP，IdP 是接收方
            // 此时 SP 是发送方，**不应验证 Destination 是否属于自身**
            // 而应由 IdP 验证。因此 SP 端通常**跳过 Destination 验证**
            // 但如果你作为 SP 也要校验（比如防止发错），可对比 IdP 的 SLO URL
            // —— 但你的 entityMeta 是 SP 自身，没有 IdP 的 SLO，所以一般不验

            // ✅ 所以：LogoutResponse 在 SP 端通常**无需验证 Destination/Recipient**
        }
            break;

        case 'AuthnRequest': // SP → IdP 的认证请求
        {
            // AuthnRequest 是 SP 发出的，不是接收的
            // 此验证逻辑运行在 SP 接收响应时，**不会收到 AuthnRequest**
            // 所以这个 case 实际不会触发，保留仅为完整性
        }
            break;

        case 'Unknown':
        default:
            // 未知类型，保守拒绝
            return Promise.reject('ERR_UNKNOWN_SAML_MESSAGE_TYPE');
    }
    return Promise.resolve({
        ...parseResult,
            verificationResult: {
            isMessageSigned:verificationResult?.isMessageSigned,
            MessageSignatureStatus:verificationResult?.MessageSignatureStatus,
            isAssertionSigned:verificationResult?.isAssertionSigned,
            AssertionSignatureStatus:verificationResult?.AssertionSignatureStatus,
            encrypted:verificationResult?.encrypted,
            decrypted:verificationResult?.decrypted,
            type:verificationResult?.type, // 添加类型字段
            status:verificationResult?.status,
            hasUnsafeSignatureAlgorithm:verificationResult?.hasUnsafeSignatureAlgorithm,
            unsafeSignatureAlgorithm:verificationResult?.unsafeSignatureAlgorithm
        },
    });

}

// proceed the post Artifact flow
async function postArtifactFlow(options): Promise<FlowResult> {

    const {
        request,
        from,
        self,
        parserType,
        checkSignature = true
    } = options;

    const {body} = request;

    const direction = libsaml.getQueryParamByType(parserType);
    const encodedRequest = body[direction];

    let samlContent = String(base64Decode(encodedRequest));

    const verificationOptions = {
        metadata: from.entityMeta,
        signatureAlgorithm: from.entitySetting.requestSignatureAlgorithm,
    };
    /** 断言是否加密应根据响应里面的字段判断*/
    let decryptRequired = from.entitySetting.isAssertionEncrypted;
    let extractorFields: ExtractorFields = [];

    // validate the xml first
    let res = await libsaml.isValidXml(samlContent, true);
    if (parserType !== urlParams.samlResponse) {
        extractorFields = getDefaultExtractorFields(parserType, null);
    }
    // check status based on different scenarios
    await checkStatus(samlContent, parserType);
    /**检查签名顺序 */



        // 改进的postFlow函数中关于签名验证的部分
    const verificationResult = await libsaml.verifySignature(samlContent, verificationOptions,self);


// 检查验证结果
    if (!verificationResult.status) {
        // 如果验证失败，根据具体情况返回错误
        if (verificationResult.isMessageSigned && !verificationResult.MessageSignatureStatus) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_MESSAGE_SIGNATURE');
        }
        if (verificationResult.isAssertionSigned && !verificationResult.AssertionSignatureStatus) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_ASSERTION_SIGNATURE');
        }
        if (verificationResult.encrypted && !verificationResult.decrypted) {
            return Promise.reject('ERR_FAIL_TO_DECRYPT_ASSERTION');
        }

        // 通用验证失败
        return Promise.reject('ERR_FAIL_TO_VERIFY_SIGNATURE_OR_DECRYPTION');
    }

// 更新samlContent为验证后的版本（可能已解密）
    samlContent = verificationResult.samlContent;

// 根据验证结果设置extractorFields
    if (verificationResult.assertionContent) {
        extractorFields = getDefaultExtractorFields(parserType, verificationResult.assertionContent);
    } else {
        // 如果没有断言内容（例如注销请求/响应），使用适当的处理方式
        extractorFields = getDefaultExtractorFields(parserType, null);
    }


    const parseResult = {
        samlContent: samlContent,
        extract: extract(samlContent, extractorFields),
    };

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const targetEntityMetadata = from.entityMeta;
    const issuer = targetEntityMetadata.getEntityID();
    const extractedProperties = parseResult.extract;

    // unmatched issuer
    if (
        (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
        && extractedProperties
        && extractedProperties.issuer !== issuer
    ) {
        return Promise.reject('ERR_UNMATCH_ISSUER');
    }

    // invalid session time
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_EXPIRED_SESSION');
    }

    // invalid time
    // 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.conditions
        && !verifyTime(
            extractedProperties.conditions.notBefore,
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_CONDITION_UNCONFIRMED');
    }
    //valid destination
    //There is no validation of the response here. The upper-layer application
    // should verify the result by itself to see if the destination is equal to the SP acs and
    // whether the response.id is used to prevent replay attacks.
    let destination = extractedProperties?.response?.destination
    let isExit = self.entitySetting?.assertionConsumerService?.filter((item) => {
        return item?.Location === destination
    })
    if (isExit?.length === 0) {
        return Promise.reject('ERR_Destination_URL');
    }
    if (parserType === 'SAMLResponse') {
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
    }


    return Promise.resolve(parseResult);
}


// proceed the post simple sign binding flow
async function postSimpleSignFlow(options): Promise<FlowResult> {

    const {request, parserType, self, checkSignature = true, from} = options;

    const {body, octetString} = request;

    const targetEntityMetadata = from.entityMeta;

    // ?SAMLRequest= or ?SAMLResponse=
    const direction = libsaml.getQueryParamByType(parserType);
    const encodedRequest: string = body[direction];
    const sigAlg: string = body['SigAlg'];
    const signature: string = body['Signature'];

    // query must contain the saml content
    if (encodedRequest === undefined) {
        return Promise.reject('ERR_SIMPLESIGN_FLOW_BAD_ARGS');
    }

    const xmlString = String(base64Decode(encodedRequest));

    // validate the xml
    try {
        await libsaml.isValidXml(xmlString, false);
    } catch (e) {
        return Promise.reject('ERR_INVALID_XML');
    }

    // check status based on different scenarios
    await checkStatus(xmlString, parserType);

    let assertion: string = '';

    if (parserType === urlParams.samlResponse) {
        // Extract assertion shortcut

        const verifiedDoc = extract(xmlString, [{
            key: 'assertion',
            localPath: ['~Response', 'Assertion'],
            attributes: [],
            context: true
        }]);

        if (verifiedDoc && verifiedDoc.assertion) {
            assertion = verifiedDoc.assertion as string;
        }
    }

    const extractorFields = getDefaultExtractorFields(parserType, assertion.length > 0 ? assertion : null);

    const parseResult: { samlContent: string, extract: any, sigAlg: (string | null) } = {
        samlContent: xmlString,
        sigAlg: null,
        extract: extract(xmlString, extractorFields),
    };

    // see if signature check is required
    // only verify message signature is enough
    if (checkSignature) {
        if (!signature || !sigAlg) {
            return Promise.reject('ERR_MISSING_SIG_ALG');
        }

        // put the below two assignments into verifyMessageSignature function
        const base64Signature = Buffer.from(signature, 'base64');

        const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

        if (!verified) {
            // Fail to verify message signature
            return Promise.reject('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION');
        }

        parseResult.sigAlg = sigAlg;
    }

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const issuer = targetEntityMetadata.getEntityID();
    const extractedProperties = parseResult.extract;

    // unmatched issuer
    if (
        (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
        && extractedProperties
        && extractedProperties.issuer !== issuer
    ) {
        return Promise.reject('ERR_UNMATCH_ISSUER');
    }

    // invalid session time
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_EXPIRED_SESSION');
    }

    // invalid time
    // 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.conditions
        && !verifyTime(
            extractedProperties.conditions.notBefore,
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_CONDITION_UNCONFIRMED');
    }

    if (parserType === 'SAMLResponse') {
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
    }


    return Promise.resolve(parseResult);
}


export function checkStatus(content: string, parserType: string, soap?: boolean): Promise<string> {

    // only check response parser
    if (parserType !== urlParams.samlResponse && parserType !== urlParams.logoutResponse) {
        return Promise.resolve('SKIPPED');
    }

    let fields = parserType === urlParams.samlResponse
        ? loginResponseStatusFields
        : logoutResponseStatusFields;
    if (soap === true) {
        fields = parserType === urlParams.samlResponse
            ? loginArtifactResponseStatusFields
            : logoutResponseStatusFields;
    }

    const {top, second} = extract(content, fields);

    // only resolve when top-tier status code is success
    if (top === StatusCode.Success) {
        return Promise.resolve('OK');
    }

    if (!top) {
        throw new Error('ERR_UNDEFINED_STATUS');
    }

    // returns a detailed error for two-tier error code
    throw new Error('ERR_UNDEFINED_STATUS');
  /*  throw new Error(`ERR_FAILED_STATUS with top tier code: ${top}, second tier code: ${second}`);*/
}

export function flow(options): Promise<FlowResult> {

    const binding = options.binding;
    const parserType = options.parserType;

    options.supportBindings = [BindingNamespace.Redirect, BindingNamespace.Post, BindingNamespace.SimpleSign];
    // saml response  allows POST, REDIRECT
    if (parserType === ParserType.SAMLResponse) {
        options.supportBindings = [BindingNamespace.Post, BindingNamespace.Redirect, BindingNamespace.SimpleSign];
    }

    if (binding === bindDict.post) {
        return postFlow(options);
    }

    if (binding === bindDict.redirect) {
        return redirectFlow(options);
    }

    if (binding === bindDict.simpleSign) {
        return postSimpleSignFlow(options);
    }


    return Promise.reject('ERR_UNEXPECTED_FLOW');

}
