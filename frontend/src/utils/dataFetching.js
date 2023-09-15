import { getXsrfToken } from "./helpers.js";

const HEADERS = {
	'Content-Type': 'application/json',
	'Accept': 'application/json',
}

const HEADERS_XSRF = {
	'Content-Type': 'application/json',
	'Accept': 'application/json',
	'X-NIOCA-XSRF': getXsrfToken(),
}

export async function fetchStatus() {
	return await fetch('/api/status', {
		method: 'GET',
		headers: HEADERS,
	});
}

export async function fetchLoginCheck() {
	return await fetch('/api/login/check', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchLoginSession() {
	return await fetch('/api/sessions', {
		method: 'POST',
		headers: HEADERS,
	});
}

// needs xsrf provided directly instead of from local storage to prevent a race condition
export async function fetchLoginLocal(data, xsrf) {
	return await fetch('/api/login', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': `Bearer ${xsrf}`,
		},
		body: JSON.stringify(data),
	});
}

export async function fetchLogout() {
	return await fetch('/api/logout', {
		method: 'POST',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetCAsSsh() {
	return await fetch('/api/ca/ssh', {
        method: 'GET',
        headers: HEADERS_XSRF,
    });
}

export async function fetchGetCAsX509() {
    return await fetch('/api/ca/x509', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetCAsX509Inspect() {
	return await fetch('/api/ca/x509/inspect', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGenerateCASshRoot(data) {
	return await fetch('/api/ca/ssh/generate', {
		method: 'POST',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchExternalCASshRoot(data) {
	return await fetch('/api/ca/ssh/external', {
		method: 'POST',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchGetClientsSsh() {
	return await fetch('/api/clients/ssh', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchPostClientsSsh(data) {
	return await fetch('/api/clients/ssh', {
		method: 'POST',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchPutClientSsh(id, data) {
	return await fetch(`/api/clients/ssh/${id}`, {
		method: 'PUT',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchDeleteClientSsh(id) {
	return await fetch(`/api/clients/ssh/${id}`, {
		method: 'DELETE',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetClientSshSecret(id) {
	return await fetch(`/api/clients/ssh/${id}/secret`, {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchPutClientSshSecret(id) {
	return await fetch(`/api/clients/ssh/${id}/secret`, {
		method: 'PUT',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetClientsX509() {
	return await fetch('/api/clients/x509', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchPostClientsX509(data) {
	return await fetch('/api/clients/x509', {
		method: 'POST',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchPutClientX509(id, data) {
	return await fetch(`/api/clients/x509/${id}`, {
		method: 'PUT',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchDeleteClientX509(id) {
	return await fetch(`/api/clients/x509/${id}`, {
		method: 'DELETE',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetClientX509Secret(id) {
	return await fetch(`/api/clients/x509/${id}/secret`, {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchPutClientX509Secret(id) {
	return await fetch(`/api/clients/x509/${id}/secret`, {
		method: 'PUT',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetConfigOidc() {
	return await fetch('/api/oidc/config', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchPutConfigOidc(data) {
	return await fetch('/api/oidc/config', {
		method: 'PUT',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchGetGroups() {
	return await fetch('/api/groups', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchPutGroups(id, data) {
	return await fetch(`/api/groups/${id}`, {
		method: 'PUT',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchGetOidcExists() {
	return await fetch('/api/oidc/exists', {
		method: 'GET',
		headers: HEADERS_XSRF,
	});
}

export async function fetchGetOidcAuth() {
	return await fetch('/api/oidc/auth', {
		method: 'GET',
		headers: HEADERS_XSRF,
		mode: 'no-cors',
		redirect: 'manual',
	});
}

export async function fetchPutPasswordChange(data) {
	return await fetch('/api/password_change', {
		method: 'PUT',
		headers: HEADERS_XSRF,
		body: JSON.stringify(data),
	});
}

export async function fetchPEM(id, secret) {
    return await fetch(`/api/clients/x509/${id}/cert`, {
        method: 'POST',
        headers: {
            'Accept': 'application/octet-stream',
            'Authorization': `Bearer ${secret}`,
        },
    });
}

export async function fetchPKCS12(id, secret) {
	return await fetch(`/api/clients/x509/${id}/cert/p12`, {
		method: 'POST',
		headers: {
			'Accept': 'application/octet-stream',
			'Authorization': `Bearer ${secret}`,
		},
	});
}

export async function fetchSshCert(id, secret) {
	return await fetch(`/api/clients/ssh/${id}/cert`, {
		method: 'POST',
		headers: {
			'Accept': 'application/json',
			'Authorization': `Bearer ${secret}`,
		},
	});
}
