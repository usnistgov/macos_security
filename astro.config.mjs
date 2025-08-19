import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
	integrations: [
		starlight({
			title: 'mSCP',
			favicon: '/favicon.png',
			logo: {
				src: './src/assets/logo.png',
			},
			customCss: [
				// Path to your custom CSS file
				'./src/styles/custom.css',
				'./src/styles/home_page.css',
			],
head: [
			  {
			    tag: 'link',
    			    attrs: {
				rel: 'stylesheet',
			        href: 'https://pages.nist.gov/nist-header-footer/css/nist-combined.css',
				},
			},
			{
                            tag: 'script',
                            attrs: {
                                src: 'https://pages.nist.gov/nist-header-footer/js/nist-header-footer-v-2.0.js',
                                type: 'text/javascript',
                                defer: 'defer',
				 },
                        },
			{
		tag: 'script',
		attrs: {
			async: 'async',
			src: 'https://www.googletagmanager.com/gtag/js?id=G-QBDGYZRSGT',
		},
	},
	{
		tag: 'script',
		children: `
			window.dataLayer = window.dataLayer || [];
			function gtag(){dataLayer.push(arguments);}
			gtag('js', new Date());
			gtag('config', 'G-QBDGYZRSGT');
		`,
	},
			],
			social: [
	{ icon: 'github', label: 'GitHub', href: 'https://github.com/usnistgov/macos_security' },
	{ icon: 'slack', label: 'Slack', href: 'https://macadmins.slack.com/archives/C0158JKQTC5' },
],
			sidebar: [
				{
					label: 'Welcome',
					collapsed: false,
					items: [
						{ label: 'Introduction', link: '/welcome/introduction/' },
						{ label: 'Getting Started', link: '/welcome/getting-started/' },
						{ label: 'Quick Guide', link: '/welcome/quick-guide/' },
					],
				},
				{
					label: 'Baselines',
					collapsed: true,
					items: [
						{ label: 'What Are Baselines?', link: '/baselines/what-are-baselines/' },
						{ label: 'How To Generate Baseline', link: '/baselines/how-to-generate-baselines/' },
						{ label: 'Baseline File Layout', link: '/baselines/baseline-file-layout/' },
						{ label: 'Tailoring a Baseline', link: '/baselines/tailoring-a-baseline/' },
					],
				},
				{
					label: 'Guidance',
					collapsed: true,
					items: [
						{ label: 'What Is Guidance?', link: '/guidance/what-is-guidance/' },
						{ label: 'How To Generate Guidance', link: '/guidance/how-to-generate-guidance/' },
						{ label: 'Guidance File Layout', link: '/guidance/guidance-file-example/' },
					],
				},
				{
					label: 'Configuration Profiles',
					collapsed: true,
					items: [
						{ label: 'What Are Configuration Profiles?', link: '/configuration-profiles/what-are-configuration-profiles/' },
						{ label: 'How to Generate Configuration Profiles', link: '/configuration-profiles/how-to-generate-configuration-profiles/' },
						{ label: 'Configuration Profile Layout', link: '/configuration-profiles/configuration-profile-layout/' },
					],
				},
				{
					label: 'DDM Components',
					collapsed: true,
					items: [
						{ label: 'What is DDM?', link: '/ddm-components/what-is-ddm/' },
						{ label: 'How to Generate DDM Components', link: '/ddm-components/how-to-generate-ddm-components/' },
						{ label: 'DDM Component Layout', link: '/ddm-components/ddm-component-layout/' },
					],
				},
				{
					label: 'Compliance Scripts',
					collapsed: true,
					items: [
						{ label: 'What Are Compliance Scripts?', link: '/compliance-scripts/what-are-compliance-scripts/' },
						{ label: 'How to Generate Compliance Scripts', link: '/compliance-scripts/how-to-generate-compliance-scripts/' },
						{ label: 'Compliance Script Layout', link: '/compliance-scripts/compliance-script-layout/' },
					],
				},
				{
					label: 'Other Generated Content',
					collapsed: true,
					items: [
						{ label: 'Generate Mapping', link: '/other/generate-mapping/' },
						{ label: 'Generate SCAP', link: '/other/generate-scap/' },
					],
				},
				{
					label: 'Personalization',
					collapsed: true,
					items: [
						{ label: 'Tailoring Rules', link: '/personalization/tailoring-rules/' },
						{ label: 'Customize Rules', link: '/personalization/customize-rules/' },
						{ label: 'Exempting Rules', link: '/personalization/exempting-rules/' },
					],
				},
				{
					label: 'Repository',
					collapsed: true,
					items: [
						{ label: 'Directory Layout', link: '/repository/directory-layout/' },
						{ label: 'Includes Directory', link: '/repository/includes-directory/' },
						{ label: 'Rules File Layout', link: '/repository/rule-file-layout/' },
						{ label: 'Sections File Layout', link: '/repository/sections-file-layout/' },
						{ label: 'Script Arguments List', link: '/repository/script-arguments-list/' },
					],
				},
				{
					label: 'More Information',
					collapsed: true,
					items: [
						{ label: 'mSCP Training/Resources', link: '/more-information/resources/' },
						{ label: 'Additional Documents', link: '/more-information/additional-documents/' },
						{ label: 'Contributing', link: '/more-information/contributing/' },
						{ label: 'Vendor Attribution', link: '/more-information/vendor-attribution/' },
						{ label: 'FAQ', link: '/more-information/faq/' },
					],
				},
			],
			editLink: {
				baseUrl: 'https://github.com/usnistgov/macos_security/edit/nist-pages/docs/',
			},
			lastUpdated: true,
		}),
	],
});

