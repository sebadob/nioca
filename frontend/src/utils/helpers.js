const XSRF_TOKEN = 'nioca_xsrf';

export function extractFormErrors(err) {
	return err.inner.reduce((acc, err) => {
		return {...acc, [err.path]: err.message};
	}, {});
}

// export function getCookie(cname) {
// 	let name = cname + "=";
// 	let decodedCookie = decodeURIComponent(document.cookie);
// 	let ca = decodedCookie.split(';');
// 	for(let i = 0; i < ca.length; i++) {
// 		let c = ca[i].trim();
// 		if (c.indexOf(name) === 0) {
// 			return c.substring(name.length, c.length);
// 		}
// 	}
// 	return "";
// }

// Uses the browsers download functionality from any given blob, no matter how it was received
export function downloadBlob(blob) {
	const url = window.URL || window.webkitURL;
	const link = url.createObjectURL(blob);

	// generate anchor tag, click it for download and then remove it again
	let a = document.createElement("a");
	a.setAttribute('download', 'x509_pkcs12.p12');
	a.setAttribute('href', link);
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
}

export const deleteXsrfToken = (token) => {
	if (isWindow()) {
		localStorage.removeItem(XSRF_TOKEN);
	}
}

export const saveXsrfToken = (token) => {
	if (isWindow()) {
		localStorage.setItem(XSRF_TOKEN, token);
	}
}

export const getXsrfToken = () => {
	if (isWindow()) {
		return localStorage.getItem(XSRF_TOKEN) || '';
	}
	return '';
}

export function isWindow() {
	return typeof window !== 'undefined';
}

// export const generatePassword = (length, minLowerCase, minUpperCase, minDigit) => {
// 	const lowerCaseNeeded = minLowerCase || 1;
// 	const upperCaseNeeded = minUpperCase || 1;
// 	const digitNeeded = minDigit || 1;
//
// 	while (true) {
// 		let pwdLength = length || 14;
// 		let lowerCaseIncluded = 0;
// 		let upperCaseIncluded = 0;
// 		let digitIncluded = 0;
// 		let pwdArr = [];
//
// 		for (let i = 0; i < pwdLength; i += 1) {
// 			let nextNumber = 60;
// 			while ((nextNumber > 57 && nextNumber < 65) || (nextNumber > 90 && nextNumber < 97)) {
// 				nextNumber = Math.floor(Math.random() * 74) + 48;
// 			}
//
// 			// check if a lower case char was already included
// 			if (nextNumber >= 91 && nextNumber <= 122) {
// 				lowerCaseIncluded += 1;
// 			}
//
// 			// check if a upper case char was already included
// 			if (nextNumber >= 65 && nextNumber <= 90) {
// 				upperCaseIncluded += 1;
// 			}
//
// 			// check if a digit was already included
// 			if (nextNumber >= 48 && nextNumber <= 57) {
// 				digitIncluded += 1;
// 			}
//
// 			pwdArr.push(String.fromCharCode(nextNumber));
// 		}
//
// 		// If not all types are included, start fresh and try again -> most random approach
// 		if (lowerCaseIncluded < lowerCaseNeeded || upperCaseIncluded < upperCaseNeeded || digitIncluded < digitNeeded) {
// 			continue;
// 		}
//
// 		return pwdArr.join('');
// 	}
// };

// export const computePow = (powChallenge) => {
// 	let start = new Date().getTime();
//
// 	let verifier = powChallenge.challenge;
// 	for (let i = 0; i < powChallenge.it; i++) {
// 		const myBitArray = sjcl.hash.sha256.hash(verifier);
// 		verifier = sjcl.codec.hex.fromBits(myBitArray);
// 	}
//
// 	let diff = new Date().getTime() - start;
// 	console.log('Time Taken for computePow: ' + diff + ' ms');
//
// 	return {
// 		challenge: powChallenge.challenge,
// 		verifier,
// 	};
// }

// async sleep in ms
export const sleepAwait = async (ms) => await new Promise(x => setTimeout(x, ms));

// Returns a short random key, which can be used in components to identify them uniquely.
export const getKey = (i) => {
	let res = '';

	const target = i || 8;
	for (let i = 0; i < target; i += 1) {
		let nextNumber = 60;
		while ((nextNumber > 57 && nextNumber < 65) || (nextNumber > 90 && nextNumber < 97)) {
			nextNumber = Math.floor(Math.random() * 74) + 48;
		}
		res = res.concat(String.fromCharCode(nextNumber));
	}

	return res;
}
