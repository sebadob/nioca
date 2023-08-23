const HEADERS = {
	'Content-Type': 'application/json',
	'Accept': 'application/json',
}

export async function postUnsealAddKEy(data) {
	return await fetch('/unseal/key', {
		method: 'POST',
		headers: HEADERS,
		body: JSON.stringify(data),
	});
}

export async function postUnsealExecute(data) {
	return await fetch('/unseal/execute', {
		method: 'POST',
		headers: HEADERS,
		body: JSON.stringify(data),
	});
}

export async function postInit(data) {
	return await fetch('/unseal/init', {
		method: 'POST',
		headers: HEADERS,
		body: JSON.stringify(data),
	});
}

export async function postInitCheck(data) {
	return await fetch('/unseal/init/check', {
		method: 'POST',
		headers: HEADERS,
		body: JSON.stringify(data),
	});
}

export async function fetchUnsealStatus() {
	return await fetch('/unseal/status', {
		method: 'GET',
		headers: HEADERS,
	});
}

export async function fetchUnsealXsrf() {
	return await fetch('/unseal/xsrf', {
		method: 'GET',
		headers: HEADERS,
	});
}
