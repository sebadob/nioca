<script>
    import {extractFormErrors, sleepAwait} from "../../utils/helpers.js";
    import Button from "$lib/Button.svelte";
    import IconKey from "$lib/icons/IconKey.svelte";
    import PasswordInput from "$lib/inputs/PasswordInput.svelte";
    import {onMount} from "svelte";
    import {
        fetchUnsealStatus,
        fetchUnsealXsrf,
        postUnsealAddKEy,
        postUnsealExecute
    } from "../../utils/dataFetchingUnseal.js";
    import CheckIcon from "../../components/CheckIcon.svelte";
    import * as yup from "yup";
    import Loading from "$lib/Loading.svelte";
    import {fetchStatus} from "../../utils/dataFetching.js";

    let isLoading = false;
    let err = '';
    let keyAdded = false;

    let status = {};

    let formValues = {};
    let formErrors = {};

    const schema = yup.object().shape({
        key: yup.string().required('Required').max(256, 'Maximum length: 256 characters'),
    });

    onMount(() => {
        getStatus();
    });

    async function getStatus() {
        let res = await fetchUnsealStatus();
        let body = await res.json();
        if (res.ok) {
            status = body;
        } else {
            err = body.msg;
        }
    }

    async function getXsrf() {
        const xsrfRes = await fetchUnsealXsrf();
        if (!xsrfRes.ok) {
            let body = await xsrfRes.json();
            err = body.message;
            return;
        }
        return await xsrfRes.text();
    }

    async function addKey() {
        err = '';

        try {
            await schema.validate(formValues, {abortEarly: false});
            formErrors = {};
        } catch (err) {
            formErrors = extractFormErrors(err);
            return;
        }

        isLoading = true;

        const xsrf = await getXsrf();

        const data = {
            key: formValues.key,
            xsrf,
        };

        let res = await postUnsealAddKEy(data);
        if (res.ok) {
            formValues.key = '';
            keyAdded = true;

            setTimeout(() => {
                keyAdded = false;
            }, status.keyAddRateLimit * 1000);

            await getStatus();
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function unseal() {
        isLoading = true;

        let xsrf = await getXsrf();
        let data = { xsrf };

        let res = await postUnsealExecute(data);
        if (res.ok) {
            // wait for 3 seconds and then fetch the backend status
            await sleepAwait(3000);

            // fetch the backend status until the server is up unsealed again
            while (true) {
                try {
                    let res = await fetchStatus().catch(e => console.error(e));

                    if (res.ok) {
                        let status = await res.json();
                        if (!status.isSealed) {
                            window.location.href = '/';
                        }
                    }
                } catch (e) {
                    console.error(e);
                    // do nothing
                }

                await sleepAwait(2000);
            }
        } else {
            let body = await res.json();
            err = body.message;
            isLoading = false;
        }
    }
</script>

<div class="container">
    <h1>Nioca is sealed</h1>

    {#if status}
        <div class="status">
            <h3>Status</h3>
            <div class="statusRow">
                <div class="statusLabel">
                    Master Key 1
                </div>
                <CheckIcon check={status.masterShard1}/>
            </div>

            <div class="statusRow">
                <div class="statusLabel">
                    Master Key 2
                </div>
                <CheckIcon check={status.masterShard2}/>
            </div>

            <div class="statusRow">
                <div class="statusLabel">
                    Unseal ready
                </div>
                <CheckIcon check={status.isReady}/>
            </div>
        </div>

        {#if !status.isReady}
            <div class="inputRow">
                <IconKey width={24}/>
                <PasswordInput
                        name="key"
                        placeholder="Master Key"
                        bind:value={formValues.key}
                        bind:error={formErrors.key}
                >
                    Master Key
                </PasswordInput>
            </div>

            {#if keyAdded}
                Waiting for key add rate limiter
            {/if}

            <Button on:click={addKey} isLoading={isLoading || keyAdded}>VALIDATE</Button>
        {/if}

        {#if status.isReady}
            <p>Nioca is ready to be unsealed</p>
            <Button on:click={unseal} isLoading={isLoading}>UNSEAL</Button>
        {/if}
    {/if}

    {#if err}
        <div class="errMain">
            {err}
        </div>
    {/if}
</div>

<style>
    .container {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }

    .errMain {
        margin: 5px;
        color: var(--col-err);
        text-align: right;
    }

    .inputRow {
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .status {
        margin-bottom: 20px;
    }

    .statusLabel {
        width: 100px;
    }

    .statusRow {
        display: flex;
        flex-direction: row;
    }
</style>
