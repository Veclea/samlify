/**
* @file metadata-idp.ts
* @author tngan
* @desc  Metadata of identity provider
*/
import Metadata, { type  MetadataInterface } from './metadata.js';
import  type { MetadataIdpOptions, MetadataIdpConstructor } from './types.js';
import { namespace } from './urn.js';
import libsaml from './libsaml.js';
import { castArrayOpt, isNonEmptyArray, isString } from './utility.js';
import xml from 'xml';

export interface IdpMetadataInterface extends MetadataInterface {

}

/*
 * @desc interface function
 */
export default function(meta: MetadataIdpConstructor) {
  return new IdpMetadata(meta);
}

export class IdpMetadata extends Metadata {

  constructor(meta: MetadataIdpConstructor) {

    const isFile = isString(meta) || meta instanceof Buffer;

    if (!isFile) {

      const {
        entityID,
        signingCert,
        encryptCert,
        wantAuthnRequestsSigned = false,
        nameIDFormat = [],
        singleSignOnService = [],
        singleLogoutService = [],
        artifactResolutionService=[]

      } = meta as MetadataIdpOptions;

      const IDPSSODescriptor: any[] = [{
        _attr: {
          WantAuthnRequestsSigned: String(wantAuthnRequestsSigned),
          protocolSupportEnumeration: namespace.names.protocol,
        },
      }];

      for(const cert of castArrayOpt(signingCert)) {
        IDPSSODescriptor.push(libsaml.createKeySection('signing', cert));
      }

      for(const cert of castArrayOpt(encryptCert)) {
        IDPSSODescriptor.push(libsaml.createKeySection('encryption', cert));
      }
      if (isNonEmptyArray(artifactResolutionService)) {
        let indexCounts = 0;
        artifactResolutionService.forEach((a, indexCount) => {
          const attr: any = {};
          /*     if (a.isDefault) {
                 attr.isDefault = true;
               }*/
          attr.index =  String(indexCounts++),
          attr.Binding = a.Binding;
          attr.Location = a.Location;
          IDPSSODescriptor.push({ ArtifactResolutionService: [{ _attr: attr }] });
        });
      } else {
        console.warn('Construct identity  provider - missing endpoint of ArtifactResolutionService');
      }
      if (isNonEmptyArray(singleLogoutService)) {
        singleLogoutService.forEach((a, indexCount) => {
          const attr: any = {};
          /*          if (a.isDefault) {
                      attr.isDefault = true;
                    }*/
          attr.Binding = a.Binding;
          attr.Location = a.Location;
          IDPSSODescriptor.push({ SingleLogoutService: [{ _attr: attr }] });
        });
      } else {
        console.warn('Construct identity  provider - missing endpoint of SingleLogoutService');
      }

      if (isNonEmptyArray(nameIDFormat)) {
        nameIDFormat.forEach(f => IDPSSODescriptor.push({ NameIDFormat: f }));
      }

      if (isNonEmptyArray(singleSignOnService)) {
        singleSignOnService.forEach((a, indexCount) => {
          const attr: any = {
            Binding: a.Binding,
            Location: a.Location,
          };
/*          if (a.isDefault) {
            attr.isDefault = true;
          }*/
          IDPSSODescriptor.push({ SingleSignOnService: [{ _attr: attr }] });
        });
      } else {
        throw new Error('ERR_IDP_METADATA_MISSING_SINGLE_SIGN_ON_SERVICE');
      }


      // Create a new metadata by setting
      meta = xml([{
        EntityDescriptor: [{
          _attr: {
            'xmlns': namespace.names.metadata,
            'xmlns:assertion': namespace.names.assertion,
            'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
            entityID,
          },
        }, { IDPSSODescriptor }],
      }]);
    }

    super(meta as string | Buffer, [
      {
        key: 'wantAuthnRequestsSigned',
        localPath: ['EntityDescriptor', 'IDPSSODescriptor'],
        attributes: ['WantAuthnRequestsSigned'],
      },
      {
        key: 'singleSignOnService',
        localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
        index: ['Binding'],
        attributePath: [],
        attributes: ['Location']
      },
      {
        key: 'artifactResolutionService',
        localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'ArtifactResolutionService'],
        index: ['Binding'],
        attributePath: [],
        attributes: ['Location']
      },
    ]);

  }

  /**
  * @desc Get the preference whether it wants a signed request
  * @return {boolean} WantAuthnRequestsSigned
  */
  isWantAuthnRequestsSigned(): boolean {
    const was = this.meta.wantAuthnRequestsSigned;
    if (was === undefined) {
      return false;
    }
    return String(was) === 'true';
  }

  /**
  * @desc Get the entity endpoint for single sign on service
  * @param  {string} binding      protocol binding (e.g. redirect, post)
  * @return {string/object} location
  */
  getSingleSignOnService(binding: string): string | object {
    if (isString(binding)) {
      const bindName = namespace.binding[binding];
      const service = this.meta.singleSignOnService[bindName];
      if (service) {
        return service;
      }
    }
    return this.meta.singleSignOnService;
  }
  /**
   * @desc Get the entity endpoint for single ArtifactResolutionService
   * @param  {string} binding      protocol binding (e.g. redirect, post)
   * @return {string/object} location
   */
  getArtifactResolutionService (binding: string): string | object {
    if (isString(binding)) {
      const bindName = namespace.binding[binding];
      const service = this.meta.artifactResolutionService[bindName];
      if (service) {
        return service;
      }
    }
    return this.meta.artifactResolutionService;
  }
}
