<script>
    import WithUnsealed from "../../components/WithUnsealed.svelte";
    import Button from "$lib/Button.svelte";
    import {slide} from "svelte/transition";
    import * as yup from "yup";
    import PasswordInput from "$lib/inputs/PasswordInput.svelte";
    import {
        fetchGetOidcAuth,
        fetchGetOidcExists,
        fetchLoginLocal,
        fetchLoginSession
    } from "../../utils/dataFetching.js";
    import {extractFormErrors, saveXsrfToken} from "../../utils/helpers.js";
    import IconKey from "../icons/IconKey.svelte";
    import {onMount} from "svelte";

    let err = '';
    let isLoading = false;
    let localDbLogin = false;
    let oidcConfigured = false;

    let formValues = {};
    let formErrors = {};

    const schema = yup.object().shape({
        password: yup.string().required('Required').min(16, 'Minimum length: 16 characters').max(128, 'Maximum length: 128 characters'),
    });

    onMount(() => {
        fetchOidcExists();
    });

    async function fetchOidcExists() {
        const res = await fetchGetOidcExists();
        if (res.ok) {
            oidcConfigured = true;
        }
    }

    function showLoginLocal() {
        localDbLogin = true;
    }

    async function loginLocal() {
        err = '';

        try {
            await schema.validate(formValues, {abortEarly: false});
            formErrors = {};
        } catch (err) {
            formErrors = extractFormErrors(err);
            return;
        }

        isLoading = true;

        const resSession = await fetchLoginSession();
        const body = await resSession.json();
        let xsrf = '';
        if (resSession.ok) {
            // TODO save expires and show a timeout counter?
            saveXsrfToken(body.xsrf);
            xsrf = body.xsrf;
        } else {
            err = body.msg;
            return;
        }

        const data = {
            password: formValues.password,
        }

        const res = await fetchLoginLocal(data, xsrf);
        if (res.ok) {
            window.location.reload();
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function oidcLogin() {
        const res = await fetchGetOidcAuth();
        if (res.status === 200) {
            window.location.href = res.headers.get('location');
        } else if (res.status === 202) {
            console.log('TODO: logged in');
        } else {
            let body = await res.json();
            err = body.message;
        }
    }

</script>

<WithUnsealed>
    <div class="container">
        <div>
            <h2>Login</h2>
        </div>

        {#if localDbLogin}
            <div transition:slide|global class="localLogin">
                <div class="inputRow">
                    <IconKey width={24}/>
                    <PasswordInput
                            name="password"
                            placeholder="Password"
                            bind:value={formValues.password}
                            bind:error={formErrors.password}
                            on:enter={loginLocal}
                    >
                        PASSWORD
                    </PasswordInput>
                </div>

                <Button on:click={loginLocal} width={150} isLoading={isLoading}>LOGIN</Button>
            </div>
        {:else}
            <div transition:slide|global>
                <Button on:click={showLoginLocal} width={150}>LOCAL LOGIN</Button>
            </div>

            {#if oidcConfigured}
                <div transition:slide|global style="margin-top: 10px;">
                    <Button on:click={oidcLogin} width={150}>SINGLE SIGN-ON</Button>
                </div>
            {/if}
        {/if}

        {#if err}
            <div class="err">
                {err}
            </div>
        {/if}
    </div>
</WithUnsealed>

<style>
    .container {
        height: 100vh;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }

    .err {
        color: var(--col-err);
    }

    .localLogin {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }

    .inputRow {
        display: flex;
        justify-content: center;
        align-items: center;
    }
</style>
