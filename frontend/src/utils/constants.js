export const REGEX_KEY_HEX = /[a-fA-F0-9]{128,1024}$/gm;
export const REGEX_INIT_KEY = /[a-zA-Z0-9]{0,128}$/gm;
export const REGEX_CA_NAME = /[a-zA-Z0-9\-_.\s]+$/gm;
export const REGEX_CLIENT_NAME = /[a-zA-Z0-9\-_.\s]+$/gm;
export const REGEX_DNS_SIMPLE = /[a-zA-Z0-9.\-*]+$/gm;
export const REGEX_JWT_CLAIM = /[a-z0-9-_/,]{2,32}$/gm;
export const REGEX_IP_V4 = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;
export const REGEX_EMAIL = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;
export const REGEX_COMMON_NAME = /[a-zA-Z0-9.*-]+$/gm;
export const REGEX_COMMON_NAME_OPT = /[a-zA-Z0-9-.*\s]*$/gm;
export const REGEX_LINUX_USER = /[a-z0-9-_@.]{2,30}$/gm;

export const OPT_X509_KEY_ALG = [
	'RSA',
	'ECDSA',
    'EdDSA',
];

export const SSH_CERT_AGLS = ['ED25519', 'ECDSAP384', 'ECDSAP256', 'RSASHA512', 'RSASHA256'];
export const SSH_CERT_TYPES = ['Host', 'User'];

export const X509_KEY_USAGES = [
	{
		label: 'DigitalSignature',
		value: false,
	},
	{
		label: 'ContentCommitment',
		value: false,
	},
	{
		label: 'DataEncipherment',
		value: false,
	},
	{
		label: 'DecipherOnly',
		value: false,
	},
	{
		label: 'EncipherOnly',
		value: false,
	},
	{
		label: 'KeyAgreement',
		value: false,
	},
	{
		label: 'KeyEncipherment',
		value: false,
	},
];

export const X509_KEY_USAGES_SSO = [
	{
		label: 'DigitalSignature',
		value: false,
	},
	{
		label: 'ContentCommitment',
		value: false,
	},
];


export const X509_KEY_USAGES_EXT = [
	{
		label: 'Any',
		value: false,
	},
	{
		label: 'ClientAuth',
		value: false,
	},
	{
		label: 'CodeSigning',
		value: false,
	},
	{
		label: 'EmailProtection',
		value: false,
	},
	{
		label: 'ServerAuth',
		value: false,
	},
	{
		label: 'TimeStamping',
		value: false,
	},
];

export const X509_KEY_USAGES_EXT_SSO = [
	{
		label: 'ClientAuth',
		value: false,
	},
	{
		label: 'CodeSigning',
		value: false,
	},
	{
		label: 'EmailProtection',
		value: false,
	},
];
