# samlify &middot;

[![Build Status](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify)
[![npm version](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify)
[![NPM](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify)
[![Coverage Status](https://img.shields.io/coveralls/tngan/samlify/master.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/tngan/samlify?branch=master)

Highly configuarable Node.js SAML 2.0 library for Single Sign On

## 🔄 此仓库为 [samlify](https://github.com/tngan/samlify) 的维护分支，修复了以下问题

- 将依赖包 @authenio/xml-encryption 更换成 xml-encryption并升级了版本,xml-encryption最新版本添加对 sha256/512 加密密钥 OAEP 摘要方法的支持，并将默认密钥签名算法指定为 sha-512
- 修复了断言加密的一些错误 如libsaml.ts对加密断言仍然采用Assertion字段提取获取，增加了EncryptedAssertion字段提取逻辑
- 默认elementsOrder增加了 AttributeConsumingService，并在参数增加了 attributeConsumingService字段能够根据字段生成attributeElement包括attributeValue
- 默认替换增加了自定义函数模板 增加了对多值的attributeValue支持与替换
- 默认替签名算法替换为SHA-256及更高，加密算法为默认AES_256_GCM模式


## Welcome PRs

Welcome all PRs for maintaining this project, or provide a link to the repositories especially for use cases alongside with different frameworks.

### Installation

Multiple schema validators are currently supported by our system, with couple validator modules available and the option to create custom ones. It is essential to utilize the setSchemaValidator function at the outset to avoid errors.

```js
import * as samlify from 'samlify';
import * as validator from '@authenio/samlify-xsd-schema-validator';
// import * as validator from '@authenio/samlify-validate-with-xmllint';
// import * as validator from '@authenio/samlify-node-xmllint';

samlify.setSchemaValidator(validator);
```

Now you can create your own schema validator and even suppress it but you have to take the risk for accepting malicious response.

```typescript
samlify.setSchemaValidator({
  validate: (response: string) => {
    /* implment your own or always returns a resolved promise to skip */
    return Promise.resolve('skipped');
  }
});
```

For those using Windows, `windows-build-tools` should be installed globally before installing samlify if you are using `libxml` validator.

```console
yarn global add windows-build-tools
```

### Development

This project is now developed using TypeScript, also support Yarn which is a new package manager.

```console
yarn global add typescript
yarn
```

### Get Started

```javascript
const saml = require('samlify');
```

See full documentation [here](https://samlify.js.org/)

### Example

[react-samlify](https://github.com/passify/react-samlify) SP example powered by React, TypeScript and Webpack

### Talks

[An introduction to Single Sign On](http://www.slideshare.net/TonyNgan/an-introduction-of-single-sign-on)

### License

[MIT](LICENSE)

### Copyright

Copyright (C) 2016-present Tony Ngan, released under the MIT License.
