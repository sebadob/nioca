import { sveltekit } from '@sveltejs/kit/vite';

/** @type {import('vite').UserConfig} */
const config = {
	plugins: [sveltekit()],
	server: {
		proxy: {
			// '/api/_app': 'http://127.0.0.1:8080',
			'/api': 'http://127.0.0.1:8080',
			'/unseal/execute': 'http://127.0.0.1:8080',
			'/unseal/init': 'http://127.0.0.1:8080',
			'/unseal/init/check': 'http://127.0.0.1:8080',
			'/unseal/key': 'http://127.0.0.1:8080',
			'/unseal/status': 'http://127.0.0.1:8080',
			'/unseal/xsrf': 'http://127.0.0.1:8080',
		}
	}
};

export default config;
