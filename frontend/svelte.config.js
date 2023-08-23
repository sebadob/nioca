import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		adapter: adapter({
			fallback: null,
			pages: '../static',
			assets: '../static',
			precompress: true,
		})
        // files: {
        // 	lib: 'src/lib',
        // }
	},
};

export default config;
