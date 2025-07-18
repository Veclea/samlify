import { DOMParser as dom } from '@xmldom/xmldom';
import type { Options as DOMParserOptions } from '@xmldom/xmldom';
interface Context extends ValidatorContext, DOMParserContext {
}
interface ValidatorContext {
    validate?: (xml: string) => Promise<any>;
}
interface DOMParserContext {
    dom: dom;
}
export declare function getContext(): Context;
export declare function setSchemaValidator(params: ValidatorContext): void;
export declare function setDOMParserOptions(options?: DOMParserOptions): void;
export {};
//# sourceMappingURL=api.d.ts.map