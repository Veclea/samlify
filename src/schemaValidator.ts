import { validateXML } from 'xmllint-wasm';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {fileURLToPath} from 'node:url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const schemas = [
  'saml-schema-protocol-2.0.xsd',
  'datatypes.dtd',
  'saml-schema-assertion-2.0.xsd',
  'xmldsig-core-schema.xsd',
  'XMLSchema.dtd',
  'xenc-schema.xsd',
  'saml-schema-metadata-2.0.xsd',
  'saml-schema-ecp-2.0.xsd',
  'saml-schema-dce-2.0.xsd'
];

export const validate = async (xml: string) => {

  const schemaPath = path.resolve(__dirname, 'schema');
  const [schema, ...preload] = await Promise.all(schemas.map(async file => ({
    fileName: file,
    contents: await fs.promises.readFile(`${schemaPath}/${file}`, 'utf-8')
  })))
  try {
    const validationResult = await validateXML({
      xml: [
        {
          fileName: 'content.xml',
          contents: xml,
        },
      ],
      extension: 'schema',
      schema: [schema.contents],
      preload: preload
    });

    if (validationResult.valid) {
      return true;
    }

    console.debug(validationResult);
    throw validationResult.errors;

  } catch (error) {

    console.error('[ERROR] validateXML', error);
    throw new Error('ERR_EXCEPTION_VALIDATE_XML');

  }

};
