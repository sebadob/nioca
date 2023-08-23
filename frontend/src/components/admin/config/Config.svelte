<script>
    import {onMount} from "svelte";
    import {fetchGetConfigOidc, fetchPutConfigOidc} from "../../../utils/dataFetching.js";
    import * as yup from "yup";
    import {REGEX_JWT_CLAIM} from "../../../utils/constants.js";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import Switch from "$lib/Switch.svelte";
    import Input from "$lib/inputs/Input.svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import Button from "$lib/Button.svelte";

    const inputWidth = '18rem';

    let err = '';
    let config = {
        adminClaimValue: '',
        userClaimValue: '',
        aud: '',
        clientId: '',
        emailVerified: true,
        iss: '',
        redirectUri: '',
        scope: '',
        secret: '',
    };
    let isLoading = false;
    let mapAdmin = false;
    let restrictAccess = false;
    let success = false;
    let timer;

    export const ADMIN_CLAIMS = [
        'roles',
        'groups',
    ]

    onMount(() => {
        fetchConfig();
        return () => clearTimeout(timer);
    })

    let formErrors = {};

    const schema = yup.object().shape({
        adminClaimValue: yup.string().trim().matches(REGEX_JWT_CLAIM, "Can only contain 'a-z0-9-_/,' with length 2 - 32"),
        userClaimValue: yup.string().trim().matches(REGEX_JWT_CLAIM, "Can only contain 'a-z0-9-_/,' with length 2 - 32"),
        aud: yup.string().trim().required('Required').matches(REGEX_JWT_CLAIM, "Can only contain 'a-z0-9-_/,' with length 2 - 32"),
        clientId: yup.string().required('Required').matches(REGEX_JWT_CLAIM, "Can only contain 'a-z0-9-_/,' with length 2 - 32"),
        emailVerified: yup.bool(),
        iss: yup.string().required('Required'),
        redirectUri: yup.string().required('Required'),
        scope: yup.string().required('Required').matches(REGEX_JWT_CLAIM, "Can only contain 'a-z0-9-_/,' with length 2 - 32"),
        secret: yup.string().required('Required'),
    });

    async function fetchConfig() {
        let res = await fetchGetConfigOidc();
        let body = await res.json();
        if (!res.ok) {
            config = {
                adminClaim: {
                    typ: 'roles',
                },
                userClaim: {
                    typ: 'groups',
                },
                aud: 'nioca',
                clientId: 'nioca',
                iss: '',
                adminClaimValue: 'nioca-admin',
                userClaimValue: 'nioca',
                emailVerified: true,
                redirectUri: `${window.location.href}api/oidc/callback`,
                scope: 'openid email profile',
                secret: '',
            };

            mapAdmin = true;
            restrictAccess = true;
        } else {
            if (body.adminClaim) {
                mapAdmin = true;
                body.adminClaimValue = body.adminClaim.value;
            } else {
                body.adminClaim = {
                    typ: 'roles',
                };
                body.adminClaimValue = 'nioca-admin';
            }
            if (body.userClaim) {
                restrictAccess = true;
                body.userClaimValue = body.userClaim.value;
            } else {
                body.userClaim = {
                    typ: 'groups',
                };
                body.userClaimValue = 'nioca-user';
            }
            config = body;
        }
    }

    async function onSubmit() {
        err = '';

        const valid = await validateForm();
        if (!valid) {
            err = 'Invalid input';
            return;
        }
        if (mapAdmin && !config.adminClaimValue) {
            formErrors.adminClaimValue = 'Required';
            err = 'Admin Claim Value is required when OIDC Admin is enabled';
            return;
        }
        if (restrictAccess && !config.userClaimValue) {
            formErrors.userClaimValue = 'Required';
            err = 'User Claim Value is required when restricted access is enabled';
            return;
        }

        // create request data
        let data = config;
        if (!mapAdmin) {
            data.adminClaim = null;
            data.adminClaimValue = null;
        } else {
            data.adminClaim.value = data.adminClaimValue;
        }
        if (!restrictAccess) {
            data.userClaim = null;
            data.adminClaimValue = null;
        } else {
            data.userClaim.value = data.userClaimValue;
        }

        isLoading = true;

        let res = await fetchPutConfigOidc(data);
        if (res.ok) {
            success = true;
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function validateForm() {
        try {
            await schema.validate(config, {abortEarly: false});
            formErrors = {};
            return true;
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

</script>

{#if config}
    <div class="content">
        <div class="desc">
            <h3>OIDC Configuration</h3>
            Set up the OpenID Connect Configuration.<br>
            The <code>redirect_uri</code> cannot be changed and needs to be added to your OIDC Provider.<br>
            Only <code>confidential</code> clients are supported and PKCE flow with <code>S256</code> is mandatory.
        </div>

        <!-- Redirect URI -->
        <div class="data">
            <div class="flex">
                <div class="label">
                    Redirect URI
                </div>
                <div class="redirectUri font-mono">
                    {config.redirectUri}
                </div>
            </div>
        </div>

        <!-- Issuer -->
        <Input
                name="iss"
                placeholder="Issuer"
                bind:value={config.iss}
                bind:error={formErrors.iss}
                on:blur={validateForm}
                width={inputWidth}
        >
            ISSUER
        </Input>

        <!-- Client ID -->
        <Input
                name="clientId"
                placeholder="Client ID"
                bind:value={config.clientId}
                bind:error={formErrors.clientId}
                on:blur={validateForm}
                width={inputWidth}
        >
            CLIENT ID
        </Input>

        <!-- Secret -->
        <Input
                name="clientId"
                placeholder="Secret Key"
                bind:value={config.secret}
                bind:error={formErrors.secret}
                on:blur={validateForm}
                width={inputWidth}
        >
            SECRET KEY
        </Input>

        <!-- Scope -->
        <div class="desc">
            The mandatory scopes are <code>openid email profile</code><br>
            You can specify additional ones according to your needs.<br>
            Separate the values with a space in between.
        </div>
        <Input
                name="scope"
                placeholder="Scope"
                bind:value={config.scope}
                bind:error={formErrors.scope}
                on:blur={validateForm}
                width={inputWidth}
        >
            SCOPE
        </Input>

        <!-- Verifications -->
        <div class="separator" style="margin-top: 15px; margin-bottom: 10px">
        </div>
        <div class="desc">
            Specify the additional <code>aud</code> claim for the verification and define if only verified E-Mails
            should be allowed.<br>
            Usually, the <code>aud</code> is the same as the Client ID.
        </div>

        <!-- Verified E-Mail -->
        <div class="data">
            <div class="flex">
                <div class="label">
                    Verified E-Mail
                </div>
                <div class="value">
                    <Switch bind:selected={config.emailVerified}/>
                </div>
            </div>
        </div>

        <!-- Audience -->
        <Input
                name="aud"
                placeholder="Audience"
                bind:value={config.aud}
                bind:error={formErrors.aud}
                on:blur={validateForm}
                width={inputWidth}
        >
            AUDIENCE
        </Input>

        <!-- OIDC Admin Mapping -->
        <div class="separator" style="margin-top: 15px; margin-bottom: 10px">
        </div>
        <div class="desc">
            To allow admin access for am OIDC user specify the JWT claim name and value it should contain.
        </div>

        <div class="data">
            <div class="flex">
                <div class="label">
                    OIDC Admin
                </div>
                <div class="value">
                    <Switch bind:selected={mapAdmin}/>
                </div>
            </div>
        </div>

        {#if mapAdmin}
            <!-- Claim Name -->
            <div class="data">
                <div class="label">
                    Admin Claim Name
                </div>
                <div class="value">
                    <OptionSelect bind:value={config.adminClaim.typ} options={ADMIN_CLAIMS}/>
                </div>
            </div>

            <!-- Claim Value -->
            <Input
                    name="adminClaimValue"
                    placeholder="Admin Claim Value"
                    bind:value={config.adminClaimValue}
                    bind:error={formErrors.adminClaimValue}
                    on:blur={validateForm}
                    width={inputWidth}
            >
                ADMIN CLAIM VALUE
            </Input>
        {/if}

        <!-- OIDC Admin Mapping -->
        <div class="separator" style="margin-top: 15px; margin-bottom: 10px"></div>
        <div class="desc">
            Filter the users which will get access depending on a role or group membership.<br>
            If disabled, all users will get "normal" access to fetch user certificates.
        </div>

        <div class="data">
            <div class="flex">
                <div class="label">
                    Restrict Access
                </div>
                <div class="value">
                    <Switch bind:selected={restrictAccess}/>
                </div>
            </div>
        </div>

        {#if restrictAccess}
            <div class="data">
                <div class="label">
                    User Claim Name
                </div>
                <div class="value">
                    <OptionSelect bind:value={config.userClaim.typ} options={ADMIN_CLAIMS}/>
                </div>
            </div>

            <!-- Claim Value -->
            <Input
                    name="userClaimValue"
                    placeholder="User Claim Value"
                    bind:value={config.userClaimValue}
                    bind:error={formErrors.userClaimValue}
                    on:blur={validateForm}
                    width={inputWidth}
            >
                USER CLAIM VALUE
            </Input>
        {/if}
        <!-- Save Button-->
        <div class="separator" style="margin-top: 15px; margin-bottom: 10px"></div>
        <div class="data">
            <Button on:click={onSubmit}>Save</Button>

            {#if success}
                <div class="success">
                    Success
                </div>
            {/if}

            {#if err}
                <div class="mainErr err">
                    {err}
                </div>
            {/if}
        </div>

        <div style="height: 20px"></div>
    </div>
{/if}

<style>
    .data {
        display: flex;
        align-items: center;
        margin: 3px 10px;
    }

    .desc {
        margin: 10px;
    }

    .err {
        color: var(--col-err);
    }

    .flex {
        display: flex;
        align-items: center;
    }

    .label {
        min-height: 30px;
        width: 145px;
        margin-right: 5px;
        padding-top: 5px;
        display: flex;
        font-weight: bold;
    }

    .mainErr, .success {
        display: flex;
        align-items: center;
        margin: 0 10px;
    }

    .redirectUri {
        margin: 5px;
    }

    .separator {
        margin: 0 10px;
        border-bottom: 1px solid var(--col-inact);
    }

    .success {
        color: var(--col-ok);
    }

    .value {
        margin-left: 5px;
        display: flex;
        align-items: center;
    }
</style>
